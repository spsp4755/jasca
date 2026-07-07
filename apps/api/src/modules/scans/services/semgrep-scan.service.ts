import { BadRequestException, Injectable, Logger, Optional, RequestTimeoutException, ServiceUnavailableException } from '@nestjs/common';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SemgrepRulesService } from '../../semgrep-rules/semgrep-rules.service';

const execFileAsync = promisify(execFile);
const DEFAULT_ARCHIVE_MAX_ENTRIES = 20000;

type ArchiveType = 'zip' | 'tar' | 'tar.gz';

export type SemgrepScanProfile = 'all' | 'security' | 'custom-only';

export interface SemgrepScanOptions {
    timeout?: string;
    /** all: 번들 룰 전체, security: security 카테고리만, custom-only: 커스텀 룰만 */
    profile?: SemgrepScanProfile;
    /** 번들 룰을 특정 언어 디렉토리로 제한 (예: ['javascript', 'python']) */
    languages?: string[];
}

interface PreparedTarget {
    targetPath: string;
    inputKind: 'file' | 'directory';
    archiveType?: ArchiveType | null;
}

/**
 * Runs semgrep against an uploaded source file/archive and returns SARIF.
 * Air-gapped by design: uses only the rules bundled at SEMGREP_RULES_PATH
 * and disables metrics/registry access.
 */
@Injectable()
export class SemgrepScanService {
    private readonly logger = new Logger(SemgrepScanService.name);
    private readonly uploadRoot = process.env.SEMGREP_UPLOAD_ROOT || path.join(os.tmpdir(), 'jasca-trivy-uploads');
    private readonly semgrepBinary = process.env.SEMGREP_BINARY_PATH || 'semgrep';
    private readonly rulesPath = process.env.SEMGREP_RULES_PATH || '/app/semgrep-rules';
    private readonly archiveMaxEntries = Number(process.env.SEMGREP_ARCHIVE_MAX_ENTRIES || DEFAULT_ARCHIVE_MAX_ENTRIES);
    private readonly activeScans = new Map<string, { cancel: () => void; startedAt: number }>();

    constructor(@Optional() private readonly semgrepRulesService?: SemgrepRulesService) { }

    async scanUploadedFile(filePath: string, options: SemgrepScanOptions = {}, operationId?: string): Promise<any> {
        const uploadDir = path.dirname(filePath);

        try {
            if (!fs.existsSync(filePath)) {
                throw new BadRequestException('Uploaded file was not found');
            }
            if (!fs.existsSync(this.rulesPath)) {
                throw new ServiceUnavailableException(
                    `Semgrep rules were not found at ${this.rulesPath}. Bundle offline rules or set SEMGREP_RULES_PATH.`,
                );
            }

            const startedAt = Date.now();
            const prepared = await this.prepareTarget(filePath);
            const timeoutMs = this.parseTimeoutMs(options.timeout || '10m');
            const customRulesDir = await this.writeCustomRules(uploadDir);
            const bundledConfigs = this.resolveBundledConfigs(options);
            if (bundledConfigs.length === 0 && !customRulesDir) {
                throw new BadRequestException('적용할 룰이 없습니다. custom-only 프로파일은 활성화된 커스텀 룰이 필요합니다.');
            }
            const args = [
                'scan',
                '--sarif',
                '--metrics=off',
                '--disable-version-check',
                '--quiet',
                ...bundledConfigs.flatMap((config) => ['--config', config]),
                ...(customRulesDir ? ['--config', customRulesDir] : []),
                prepared.targetPath,
            ];
            this.logger.log(`Semgrep scan prepared. operationId=${operationId || 'n/a'} input=${prepared.inputKind} file=${path.basename(filePath)}`);

            const stdout = await this.runSemgrep(args, timeoutMs, operationId);
            const result = JSON.parse(stdout);
            // Same evidence convention as the other scanner services
            result.Metadata = result.Metadata || {};
            result.Metadata.JascaScanEvidence = {
                executedBy: 'jasca',
                scanner: 'semgrep',
                sourceType: 'SARIF',
                completed: true,
                startedAt: new Date(startedAt).toISOString(),
                completedAt: new Date().toISOString(),
                durationMs: Date.now() - startedAt,
                originalFileName: path.basename(filePath),
                inputKind: prepared.inputKind,
                archiveType: prepared.archiveType,
                options: {
                    profile: options.profile || 'all',
                    languages: options.languages || [],
                    timeout: options.timeout || '10m',
                    customRulesApplied: Boolean(customRulesDir),
                },
            };
            return result;
        } catch (error) {
            if (error instanceof BadRequestException || error instanceof RequestTimeoutException || error instanceof ServiceUnavailableException) {
                throw error;
            }

            const details = [
                (error as any)?.stderr,
                (error as any)?.stdout,
                (error as Error).message,
            ].filter(Boolean).join('\n');
            this.logger.error(`Semgrep scan failed: ${(error as Error).message}${details ? `\n${this.truncateLog(details)}` : ''}`);
            throw new ServiceUnavailableException(`Semgrep scan failed: ${(error as Error).message}${details ? `: ${this.truncateLog(details)}` : ''}`);
        } finally {
            this.cleanupUploadDir(uploadDir);
        }
    }

    cancelScan(operationId: string): boolean {
        const activeScan = this.activeScans.get(operationId);
        if (!activeScan) {
            this.logger.warn(`Semgrep scan cancellation requested but no running process was found. operationId=${operationId}`);
            return false;
        }
        activeScan.cancel();
        return true;
    }

    /**
     * Resolve which bundled rule directories to pass as --config, based on
     * the scan profile and language filter (Checkmarx preset-style scoping).
     */
    private resolveBundledConfigs(options: SemgrepScanOptions): string[] {
        if (options.profile === 'custom-only') return [];

        let bases = [this.rulesPath];
        const languages = (options.languages || [])
            .map((lang) => String(lang).toLowerCase().replace(/[^a-z0-9_-]/g, ''))
            .filter(Boolean);

        if (languages.length > 0) {
            const resolved = languages
                .map((lang) => path.join(this.rulesPath, lang))
                .filter((dir) => fs.existsSync(dir));
            if (resolved.length === 0) {
                const available = fs.readdirSync(this.rulesPath, { withFileTypes: true })
                    .filter((entry) => entry.isDirectory())
                    .map((entry) => entry.name)
                    .join(', ');
                throw new BadRequestException(`지원하지 않는 언어입니다: ${languages.join(', ')}. 사용 가능: ${available}`);
            }
            bases = resolved;
        }

        if (options.profile !== 'security') return bases;

        // security profile: collect nested */security directories under each base
        const securityDirs = bases.flatMap((base) => this.findSecurityDirs(base, 4));
        // a base without any security subdir (e.g. dockerfile/security IS the base) falls back to itself
        return securityDirs.length > 0 ? securityDirs : bases;
    }

    private findSecurityDirs(base: string, maxDepth: number): string[] {
        if (maxDepth < 0 || !fs.existsSync(base)) return [];
        const found: string[] = [];
        for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
            if (!entry.isDirectory()) continue;
            const full = path.join(base, entry.name);
            if (entry.name === 'security') {
                found.push(full);
            } else {
                found.push(...this.findSecurityDirs(full, maxDepth - 1));
            }
        }
        return found;
    }

    /**
     * Write the admin-managed custom rules (CxQL-style) next to the upload so
     * semgrep merges them with the bundled ruleset for this scan.
     */
    private async writeCustomRules(uploadDir: string): Promise<string | null> {
        if (!this.semgrepRulesService) return null;

        let rules: Array<{ id: string; name: string; yaml: string }>;
        try {
            rules = await this.semgrepRulesService.getActiveRuleYamls();
        } catch (error) {
            this.logger.warn(`Failed to load custom semgrep rules, scanning with bundled rules only: ${(error as Error).message}`);
            return null;
        }
        if (rules.length === 0) return null;

        const dir = path.join(uploadDir, 'custom-rules');
        fs.mkdirSync(dir, { recursive: true });
        for (const rule of rules) {
            const safeName = rule.name.replace(/[^A-Za-z0-9._-]+/g, '-') || rule.id;
            fs.writeFileSync(path.join(dir, `${safeName}.yaml`), rule.yaml, 'utf-8');
        }
        this.logger.log(`Merged ${rules.length} custom semgrep rule file(s) into the scan`);
        return dir;
    }

    private async prepareTarget(filePath: string): Promise<PreparedTarget> {
        const archiveType = this.detectArchiveType(filePath);
        if (!archiveType) {
            return { targetPath: filePath, inputKind: 'file', archiveType: null };
        }

        await this.validateArchiveEntries(filePath, archiveType);
        const extractDir = path.join(path.dirname(filePath), 'extracted');
        fs.mkdirSync(extractDir, { recursive: true });
        await this.extractArchive(filePath, archiveType, extractDir);
        return { targetPath: extractDir, inputKind: 'directory', archiveType };
    }

    private runSemgrep(args: string[], timeoutMs: number, operationId?: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const child = spawn(this.semgrepBinary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
            const stdoutChunks: Buffer[] = [];
            const stderrChunks: Buffer[] = [];
            let cancelledByUser = false;
            let timedOut = false;
            let settled = false;
            let killTimer: NodeJS.Timeout | undefined;

            const terminate = () => {
                if (child.killed) return;
                child.kill('SIGTERM');
                killTimer = setTimeout(() => {
                    if (!child.killed) child.kill('SIGKILL');
                }, 5000);
            };

            const timeoutTimer = setTimeout(() => {
                timedOut = true;
                terminate();
            }, timeoutMs);

            if (operationId) {
                this.activeScans.set(operationId, {
                    startedAt: Date.now(),
                    cancel: () => {
                        cancelledByUser = true;
                        terminate();
                    },
                });
            }

            child.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
            child.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

            child.on('error', (error) => {
                clearTimeout(timeoutTimer);
                if (killTimer) clearTimeout(killTimer);
                if (operationId) this.activeScans.delete(operationId);
                settled = true;
                reject(error);
            });

            child.on('close', (code, signal) => {
                if (settled) return;
                settled = true;
                clearTimeout(timeoutTimer);
                if (killTimer) clearTimeout(killTimer);
                if (operationId) this.activeScans.delete(operationId);

                const stdout = Buffer.concat(stdoutChunks).toString('utf-8');
                const stderr = Buffer.concat(stderrChunks).toString('utf-8');

                if (cancelledByUser) {
                    reject(new BadRequestException('Semgrep scan was cancelled by the user'));
                    return;
                }

                if (timedOut) {
                    reject(new RequestTimeoutException(`Semgrep scan timed out after ${timeoutMs}ms`));
                    return;
                }

                // semgrep exits 1 when findings exist; only >1 is a real failure
                if (code !== 0 && code !== 1) {
                    const error = new Error(signal ? `Semgrep exited with signal ${signal}` : `Semgrep exited with code ${code}`);
                    (error as any).stdout = stdout;
                    (error as any).stderr = stderr;
                    reject(error);
                    return;
                }

                resolve(stdout);
            });
        });
    }

    private detectArchiveType(filePath: string): ArchiveType | null {
        const lowerName = path.basename(filePath).toLowerCase();
        if (lowerName.endsWith('.zip')) return 'zip';
        if (lowerName.endsWith('.tar.gz') || lowerName.endsWith('.tgz')) return 'tar.gz';
        if (lowerName.endsWith('.tar')) return 'tar';
        return null;
    }

    private async validateArchiveEntries(filePath: string, archiveType: ArchiveType): Promise<void> {
        const entries = await this.listArchiveEntries(filePath, archiveType);
        if (entries.length === 0) {
            throw new BadRequestException('Archive is empty or cannot be inspected');
        }
        if (entries.length > this.archiveMaxEntries) {
            throw new BadRequestException(`Archive has too many files. Maximum allowed entries: ${this.archiveMaxEntries}`);
        }

        for (const entry of entries) {
            const normalized = entry.replace(/\\/g, '/').trim();
            const parts = normalized.split('/').filter(Boolean);
            const isUnsafe = normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized) || parts.some((part) => part === '..');
            if (isUnsafe) {
                throw new BadRequestException(`Archive contains an unsafe path: ${entry}`);
            }
        }
    }

    private async listArchiveEntries(filePath: string, archiveType: ArchiveType): Promise<string[]> {
        const command = archiveType === 'zip' ? 'unzip' : 'tar';
        const args = archiveType === 'zip'
            ? ['-Z1', filePath]
            : [archiveType === 'tar.gz' ? '-tzf' : '-tf', filePath];

        try {
            const { stdout } = await execFileAsync(command, args, { timeout: 60 * 1000, maxBuffer: 10 * 1024 * 1024 });
            return stdout.split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean);
        } catch {
            throw new BadRequestException(`${archiveType} archive could not be inspected. Check that the file is valid.`);
        }
    }

    private async extractArchive(filePath: string, archiveType: ArchiveType, extractDir: string): Promise<void> {
        const command = archiveType === 'zip' ? 'unzip' : 'tar';
        const args = archiveType === 'zip'
            ? ['-q', filePath, '-d', extractDir]
            : [archiveType === 'tar.gz' ? '-xzf' : '-xf', filePath, '-C', extractDir];

        try {
            await execFileAsync(command, args, { timeout: 5 * 60 * 1000, maxBuffer: 20 * 1024 * 1024 });
        } catch {
            if (archiveType === 'zip' && this.hasExtractedFiles(extractDir)) {
                return;
            }
            throw new BadRequestException(`${archiveType} archive could not be extracted. Check that the file is valid.`);
        }
    }

    private hasExtractedFiles(directory: string): boolean {
        if (!fs.existsSync(directory)) return false;
        const entries = fs.readdirSync(directory, { withFileTypes: true });
        return entries.some((entry) => (
            entry.isFile()
            || (entry.isDirectory() && this.hasExtractedFiles(path.join(directory, entry.name)))
        ));
    }

    private parseTimeoutMs(timeout: string): number {
        const match = timeout.match(/^(\d+)(s|m|h)?$/);
        if (!match) return 10 * 60 * 1000;
        const value = Number(match[1]);
        const unit = match[2] || 's';
        if (unit === 'h') return value * 60 * 60 * 1000;
        if (unit === 'm') return value * 60 * 1000;
        return value * 1000;
    }

    private truncateLog(value: string, maxLength = 2000): string {
        const normalized = value.replace(/\s+$/g, '');
        return normalized.length > maxLength ? `${normalized.slice(0, maxLength)}...` : normalized;
    }

    private cleanupUploadDir(uploadDir: string): void {
        const resolvedRoot = path.resolve(this.uploadRoot);
        const resolvedDir = path.resolve(uploadDir);
        if (!resolvedDir.startsWith(resolvedRoot)) {
            this.logger.warn(`Skipped cleanup outside upload root: ${resolvedDir}`);
            return;
        }
        fs.rmSync(resolvedDir, { recursive: true, force: true });
    }
}
