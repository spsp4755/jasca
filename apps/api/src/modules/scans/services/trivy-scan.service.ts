import { BadRequestException, Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SettingsService } from '../../settings/settings.service';

const execFileAsync = promisify(execFile);
const DEFAULT_ARCHIVE_MAX_ENTRIES = 20000;

interface TrivySettings {
    outputFormat: string;
    schemaVersion: number;
    severities: string[];
    ignoreUnfixed: boolean;
    timeout: string;
    cacheDir: string;
    scanners: string[];
}

export interface TrivyScanOptions {
    offlineScan?: boolean;
    skipDbUpdate?: boolean;
    skipJavaDbUpdate?: boolean;
    ignoreUnfixed?: boolean;
    severities?: string[];
    scanners?: string[];
    timeout?: string;
}

type ArchiveType = 'zip' | 'tar' | 'tar.gz';

@Injectable()
export class TrivyScanService {
    private readonly logger = new Logger(TrivyScanService.name);
    private readonly uploadRoot = path.join(os.tmpdir(), 'jasca-trivy-uploads');
    private readonly trivyBinary = process.env.TRIVY_BINARY_PATH || 'trivy';
    private readonly defaultCacheDir = process.env.TRIVY_CACHE_DIR || path.resolve(process.cwd(), '..', '..', 'trivy-db');
    private readonly archiveMaxEntries = Number(process.env.TRIVY_ARCHIVE_MAX_ENTRIES || DEFAULT_ARCHIVE_MAX_ENTRIES);
    private readonly activeScans = new Map<string, () => void>();

    constructor(private readonly settingsService: SettingsService) { }

    async scanUploadedFile(filePath: string, options: TrivyScanOptions = {}, operationId?: string): Promise<any> {
        const uploadDir = path.dirname(filePath);

        try {
            if (!fs.existsSync(filePath)) {
                throw new BadRequestException('Uploaded file was not found');
            }

            const scanTarget = await this.prepareScanTarget(filePath, uploadDir);
            const settings = await this.getTrivySettings();
            const normalizedOptions = this.normalizeScanOptions(options);
            const effectiveTimeout = normalizedOptions.timeout || settings.timeout;
            const args = this.buildTrivyArgs(settings, scanTarget, normalizedOptions);
            const timeoutMs = this.parseTimeoutMs(effectiveTimeout);

            const stdout = await this.runTrivy(args, timeoutMs, operationId);

            return JSON.parse(stdout);
        } catch (error) {
            const stdout = (error as any)?.stdout;
            if (stdout) {
                try {
                    return JSON.parse(stdout);
                } catch {
                    // Fall through to a readable error below.
                }
            }

            if (error instanceof BadRequestException) {
                throw error;
            }

            const details = [
                (error as any)?.stderr,
                (error as any)?.stdout,
                (error as Error).message,
            ].filter(Boolean).join('\n');

            if (details.includes('first run cannot skip downloading DB') || details.includes('DB error')) {
                throw new ServiceUnavailableException(
                    'Trivy vulnerability DB is not available. Import or bundle trivy-db before running offline scans.',
                );
            }

            this.logger.error(`Trivy scan failed: ${(error as Error).message}`, (error as Error).stack);
            throw new ServiceUnavailableException(`Trivy scan failed: ${(error as Error).message}`);
        } finally {
            this.cleanupUploadDir(uploadDir);
        }
    }

    cancelScan(operationId: string): boolean {
        const cancel = this.activeScans.get(operationId);
        if (!cancel) {
            return false;
        }

        cancel();
        return true;
    }

    private runTrivy(args: string[], timeoutMs: number, operationId?: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const child = spawn(this.trivyBinary, args, {
                stdio: ['ignore', 'pipe', 'pipe'],
            });
            const stdoutChunks: Buffer[] = [];
            const stderrChunks: Buffer[] = [];
            let cancelled = false;
            let timedOut = false;
            let killTimer: NodeJS.Timeout | undefined;

            const terminate = () => {
                if (child.killed) return;
                child.kill('SIGTERM');
                killTimer = setTimeout(() => {
                    if (!child.killed) {
                        child.kill('SIGKILL');
                    }
                }, 5000);
            };

            const timeoutTimer = setTimeout(() => {
                timedOut = true;
                terminate();
            }, timeoutMs);

            if (operationId) {
                this.activeScans.set(operationId, () => {
                    cancelled = true;
                    terminate();
                });
            }

            child.stdout.on('data', (chunk: Buffer) => {
                stdoutChunks.push(chunk);
                if (Buffer.concat(stdoutChunks).length > 100 * 1024 * 1024) {
                    terminate();
                    reject(new Error('Trivy output exceeded the 100MB limit'));
                }
            });

            child.stderr.on('data', (chunk: Buffer) => {
                stderrChunks.push(chunk);
            });

            child.on('error', (error) => {
                clearTimeout(timeoutTimer);
                if (killTimer) clearTimeout(killTimer);
                if (operationId) this.activeScans.delete(operationId);
                reject(error);
            });

            child.on('close', (code) => {
                clearTimeout(timeoutTimer);
                if (killTimer) clearTimeout(killTimer);
                if (operationId) this.activeScans.delete(operationId);

                const stdout = Buffer.concat(stdoutChunks).toString('utf-8');
                const stderr = Buffer.concat(stderrChunks).toString('utf-8');

                if (cancelled) {
                    reject(new BadRequestException('Trivy scan was cancelled by the user'));
                    return;
                }

                if (timedOut) {
                    reject(new Error(`Trivy scan timed out after ${timeoutMs}ms`));
                    return;
                }

                if (code !== 0) {
                    const error = new Error(`Trivy exited with code ${code}`);
                    (error as any).stdout = stdout;
                    (error as any).stderr = stderr;
                    reject(error);
                    return;
                }

                resolve(stdout);
            });
        });
    }

    private async prepareScanTarget(filePath: string, uploadDir: string): Promise<string> {
        const archiveType = this.detectArchiveType(filePath);
        if (!archiveType) {
            return uploadDir;
        }

        const extractDir = path.join(uploadDir, 'extracted');
        fs.mkdirSync(extractDir, { recursive: true });

        await this.validateArchiveEntries(filePath, archiveType);
        await this.extractArchive(filePath, archiveType, extractDir);

        return extractDir;
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
            if (!normalized) continue;

            const parts = normalized.split('/').filter(Boolean);
            const isUnsafe =
                normalized.startsWith('/') ||
                /^[a-zA-Z]:/.test(normalized) ||
                parts.some((part) => part === '..');

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
            const { stdout } = await execFileAsync(command, args, {
                timeout: 60 * 1000,
                maxBuffer: 10 * 1024 * 1024,
            });
            return stdout.split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean);
        } catch (error) {
            this.logger.warn(`Failed to inspect archive ${path.basename(filePath)}: ${(error as Error).message}`);
            throw new BadRequestException(`${archiveType} archive could not be inspected. Check that the file is valid.`);
        }
    }

    private async extractArchive(filePath: string, archiveType: ArchiveType, extractDir: string): Promise<void> {
        const command = archiveType === 'zip' ? 'unzip' : 'tar';
        const args = archiveType === 'zip'
            ? ['-q', filePath, '-d', extractDir]
            : [archiveType === 'tar.gz' ? '-xzf' : '-xf', filePath, '-C', extractDir];

        try {
            await execFileAsync(command, args, {
                timeout: 5 * 60 * 1000,
                maxBuffer: 20 * 1024 * 1024,
            });
        } catch (error) {
            this.logger.warn(`Failed to extract archive ${path.basename(filePath)}: ${(error as Error).message}`);
            throw new BadRequestException(`${archiveType} archive could not be extracted. Check that the file is valid.`);
        }
    }

    private async getTrivySettings(): Promise<TrivySettings> {
        const defaults: TrivySettings = {
            outputFormat: 'json',
            schemaVersion: 2,
            severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            ignoreUnfixed: false,
            timeout: '10m',
            cacheDir: this.defaultCacheDir,
            scanners: ['vuln', 'secret', 'misconfig'],
        };

        try {
            const settings = await this.settingsService.get('trivy') as Partial<TrivySettings>;
            const merged = { ...defaults, ...(settings || {}) };

            // The historical UI default was /tmp/trivy-cache, but offline Docker uses TRIVY_CACHE_DIR.
            if (!settings?.cacheDir || settings.cacheDir === '/tmp/trivy-cache') {
                merged.cacheDir = this.defaultCacheDir;
            }

            return merged;
        } catch {
            return defaults;
        }
    }

    private buildTrivyArgs(settings: TrivySettings, targetPath: string, options: TrivyScanOptions): string[] {
        const severities = options.severities?.length
            ? options.severities.join(',')
            : settings.severities?.length
                ? settings.severities.join(',')
                : 'CRITICAL,HIGH,MEDIUM,LOW';
        const scanners = options.scanners?.length
            ? options.scanners.join(',')
            : settings.scanners?.length
                ? settings.scanners.map((scanner) => scanner === 'config' ? 'misconfig' : scanner).join(',')
                : 'vuln,secret,misconfig';
        const timeout = options.timeout || settings.timeout || '10m';
        const skipDbUpdate = options.skipDbUpdate !== false;
        const skipJavaDbUpdate = options.skipJavaDbUpdate !== false;
        const ignoreUnfixed = options.ignoreUnfixed ?? settings.ignoreUnfixed;

        const args = [
            'fs',
            '--format',
            'json',
            '--cache-dir',
            settings.cacheDir,
        ];

        if (skipDbUpdate) {
            args.push('--skip-db-update');
        }

        if (skipJavaDbUpdate) {
            args.push('--skip-java-db-update');
        }

        if (options.offlineScan) {
            args.push('--offline-scan');
        }

        args.push(
            '--severity',
            severities,
            '--scanners',
            scanners,
            '--timeout',
            timeout,
        );

        if (ignoreUnfixed) {
            args.push('--ignore-unfixed');
        }

        args.push(targetPath);
        return args;
    }

    private normalizeScanOptions(options: TrivyScanOptions): TrivyScanOptions {
        const allowedSeverities = new Set(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
        const allowedScanners = new Set(['vuln', 'secret', 'misconfig']);

        const severities = options.severities
            ?.map((severity) => severity.toUpperCase())
            .filter((severity) => allowedSeverities.has(severity));
        const scanners = options.scanners
            ?.map((scanner) => scanner === 'config' ? 'misconfig' : scanner)
            .filter((scanner) => allowedScanners.has(scanner));
        const timeout = options.timeout?.trim();

        if (timeout && !/^\d+(s|m|h)?$/.test(timeout)) {
            throw new BadRequestException('Invalid Trivy timeout. Use values like 30s, 10m, or 1h.');
        }

        return {
            offlineScan: options.offlineScan === true,
            skipDbUpdate: options.skipDbUpdate !== false,
            skipJavaDbUpdate: options.skipJavaDbUpdate !== false,
            ignoreUnfixed: options.ignoreUnfixed === true,
            severities: severities?.length ? severities : undefined,
            scanners: scanners?.length ? scanners : undefined,
            timeout: timeout || undefined,
        };
    }

    private parseTimeoutMs(timeout: string): number {
        const match = timeout?.match(/^(\d+)(s|m|h)?$/);
        if (!match) return 10 * 60 * 1000;

        const value = Number(match[1]);
        const unit = match[2] || 's';
        if (unit === 'h') return value * 60 * 60 * 1000;
        if (unit === 'm') return value * 60 * 1000;
        return value * 1000;
    }

    private cleanupUploadDir(uploadDir: string) {
        const resolvedRoot = path.resolve(this.uploadRoot);
        const resolvedDir = path.resolve(uploadDir);

        if (!resolvedDir.startsWith(resolvedRoot)) {
            this.logger.warn(`Skipped cleanup outside upload root: ${resolvedDir}`);
            return;
        }

        fs.rmSync(resolvedDir, { recursive: true, force: true });
    }
}
