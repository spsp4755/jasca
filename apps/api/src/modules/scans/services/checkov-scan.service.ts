import { BadRequestException, Injectable, Logger, RequestTimeoutException, ServiceUnavailableException } from '@nestjs/common';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SettingsService } from '../../settings/settings.service';

const execFileAsync = promisify(execFile);
const DEFAULT_ARCHIVE_MAX_ENTRIES = 20000;

type ArchiveType = 'zip' | 'tar' | 'tar.gz';
type CheckovInputKind = 'file' | 'directory';

export interface CheckovScanOptions {
    frameworks?: string[];
    checks?: string[];
    skipChecks?: string[];
    downloadExternalModules?: boolean;
    quiet?: boolean;
    timeout?: string;
}

interface CheckovSettings {
    allowInternalModuleDownload: boolean;
}

interface PreparedCheckovTarget {
    targetPath: string;
    inputKind: CheckovInputKind;
    archiveType?: ArchiveType | null;
}

@Injectable()
export class CheckovScanService {
    private readonly logger = new Logger(CheckovScanService.name);
    private readonly uploadRoot = process.env.CHECKOV_UPLOAD_ROOT || path.join(os.tmpdir(), 'jasca-trivy-uploads');
    private readonly checkovBinary = process.env.CHECKOV_BINARY_PATH || 'checkov';
    private readonly archiveMaxEntries = Number(process.env.CHECKOV_ARCHIVE_MAX_ENTRIES || DEFAULT_ARCHIVE_MAX_ENTRIES);
    private readonly activeScans = new Map<string, { cancel: () => void; startedAt: number }>();

    constructor(private readonly settingsService?: SettingsService) { }

    async scanUploadedFile(filePath: string, options: CheckovScanOptions = {}, operationId?: string): Promise<any> {
        const uploadDir = path.dirname(filePath);

        try {
            if (!fs.existsSync(filePath)) {
                throw new BadRequestException('Uploaded file was not found');
            }

            const startedAt = Date.now();
            const prepared = await this.prepareTarget(filePath);
            const settings = await this.getCheckovSettings();
            const normalizedOptions = this.normalizeScanOptions(options, settings);
            const timeoutMs = this.parseTimeoutMs(normalizedOptions.timeout || '10m');
            const args = this.buildCheckovArgs(prepared, normalizedOptions);
            this.logger.log(`Checkov scan prepared. operationId=${operationId || 'n/a'} input=${prepared.inputKind} file=${path.basename(filePath)}`);

            const stdout = await this.runCheckov(args, timeoutMs, operationId);
            const result = JSON.parse(stdout);
            this.attachExecutionEvidence(result, {
                executedBy: 'jasca',
                scanner: 'checkov',
                completed: true,
                startedAt: new Date(startedAt).toISOString(),
                completedAt: new Date().toISOString(),
                durationMs: Date.now() - startedAt,
                originalFileName: path.basename(filePath),
                inputKind: prepared.inputKind,
                archiveType: prepared.archiveType,
                options: normalizedOptions,
                command: [this.checkovBinary, ...this.redactArgs(args, prepared)].join(' '),
            });
            return result;
        } catch (error) {
            if (error instanceof BadRequestException || error instanceof RequestTimeoutException) {
                throw error;
            }

            const details = [
                (error as any)?.stderr,
                (error as any)?.stdout,
                (error as Error).message,
            ].filter(Boolean).join('\n');
            this.logger.error(`Checkov scan failed: ${(error as Error).message}${details ? `\n${this.truncateLog(details)}` : ''}`);
            throw new ServiceUnavailableException(`Checkov scan failed: ${(error as Error).message}${details ? `: ${this.truncateLog(details)}` : ''}`);
        } finally {
            this.cleanupUploadDir(uploadDir);
        }
    }

    cancelScan(operationId: string): boolean {
        const activeScan = this.activeScans.get(operationId);
        if (!activeScan) {
            this.logger.warn(`Checkov scan cancellation requested but no running process was found. operationId=${operationId}`);
            return false;
        }

        activeScan.cancel();
        return true;
    }

    private normalizeScanOptions(options: CheckovScanOptions, settings: CheckovSettings = { allowInternalModuleDownload: false }): Required<CheckovScanOptions> {
        const allowedFrameworks = new Set([
            'terraform',
            'terraform_plan',
            'cloudformation',
            'kubernetes',
            'helm',
            'kustomize',
            'dockerfile',
            'serverless',
            'arm',
            'bicep',
            'openapi',
            'github_actions',
            'gitlab_ci',
            'bitbucket_pipelines',
            'secrets',
            'ansible',
            'all',
        ]);

        const normalizeList = (values?: string[]) => (values || [])
            .flatMap((value) => String(value).split(','))
            .map((value) => value.trim())
            .filter(Boolean);

        const frameworks = normalizeList(options.frameworks)
            .map((value) => value.toLowerCase())
            .filter((value) => allowedFrameworks.has(value));
        const checks = normalizeList(options.checks);
        const skipChecks = normalizeList(options.skipChecks);
        const timeout = options.timeout?.trim() || '10m';

        if (!/^\d+(s|m|h)?$/.test(timeout)) {
            throw new BadRequestException('Invalid Checkov timeout. Use values like 30s, 10m, or 1h.');
        }

        return {
            frameworks,
            checks,
            skipChecks,
            // Closed-network default: only the admin-controlled setting can enable internal module repositories.
            downloadExternalModules: settings.allowInternalModuleDownload === true,
            quiet: options.quiet !== false,
            timeout,
        };
    }

    private async getCheckovSettings(): Promise<CheckovSettings> {
        const defaults: CheckovSettings = { allowInternalModuleDownload: false };
        if (!this.settingsService) return defaults;

        try {
            const stored = await this.settingsService.get('checkov') as Partial<CheckovSettings> | null;
            return {
                ...defaults,
                ...(stored || {}),
                allowInternalModuleDownload: stored?.allowInternalModuleDownload === true,
            };
        } catch (error) {
            this.logger.warn(`Failed to load Checkov settings, using closed-network defaults: ${(error as Error).message}`);
            return defaults;
        }
    }

    private buildCheckovArgs(target: PreparedCheckovTarget, options: Required<CheckovScanOptions>): string[] {
        const args = [
            target.inputKind === 'file' ? '-f' : '-d',
            target.targetPath,
            '--output',
            'json',
            '--soft-fail',
            '--compact',
            '--download-external-modules',
            options.downloadExternalModules ? 'true' : 'false',
        ];

        if (options.quiet) {
            args.push('--quiet');
        }

        if (options.frameworks.length > 0 && !options.frameworks.includes('all')) {
            args.push('--framework', ...options.frameworks);
        }

        if (options.checks.length > 0) {
            args.push('--check', options.checks.join(','));
        }

        if (options.skipChecks.length > 0) {
            args.push('--skip-check', options.skipChecks.join(','));
        }

        return args;
    }

    private async prepareTarget(filePath: string): Promise<PreparedCheckovTarget> {
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

    private runCheckov(args: string[], timeoutMs: number, operationId?: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const child = spawn(this.checkovBinary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
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
                    reject(new BadRequestException('Checkov scan was cancelled by the user'));
                    return;
                }

                if (timedOut) {
                    reject(new RequestTimeoutException(`Checkov scan timed out after ${timeoutMs}ms`));
                    return;
                }

                if (code !== 0) {
                    const error = new Error(signal ? `Checkov exited with signal ${signal}` : `Checkov exited with code ${code}`);
                    (error as any).stdout = stdout;
                    (error as any).stderr = stderr;
                    reject(error);
                    return;
                }

                if (/There are no runners to run/i.test(stderr)) {
                    reject(new BadRequestException(
                        'Checkov could not find a compatible runner for this file/framework. For Helm or Kustomize, make sure the image includes the required CLI; for CI workflows, upload an archive that preserves the repository path.',
                    ));
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

    private redactArgs(args: string[], target: PreparedCheckovTarget): string[] {
        const targetPath = path.resolve(target.targetPath);
        const uploadDir = path.dirname(targetPath);
        return args.map((arg) => {
            const resolved = path.resolve(arg);
            if (resolved === targetPath) return target.inputKind === 'file' ? `<upload:${path.basename(targetPath)}>` : '<upload-dir>';
            if (resolved.startsWith(uploadDir + path.sep)) return `<upload:${path.basename(arg)}>`;
            return /\s/.test(arg) ? JSON.stringify(arg) : arg;
        });
    }

    private attachExecutionEvidence(result: any, evidence: Record<string, unknown>): void {
        if (Array.isArray(result)) {
            result.forEach((item) => this.attachExecutionEvidence(item, evidence));
            return;
        }
        result.Metadata = result.Metadata || {};
        result.Metadata.JascaScanEvidence = evidence;
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
