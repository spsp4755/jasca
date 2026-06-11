import { BadRequestException, Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SettingsService } from '../../settings/settings.service';

const execFileAsync = promisify(execFile);

interface TrivySettings {
    outputFormat: string;
    schemaVersion: number;
    severities: string[];
    ignoreUnfixed: boolean;
    timeout: string;
    cacheDir: string;
    scanners: string[];
}

@Injectable()
export class TrivyScanService {
    private readonly logger = new Logger(TrivyScanService.name);
    private readonly uploadRoot = path.join(os.tmpdir(), 'jasca-trivy-uploads');
    private readonly trivyBinary = process.env.TRIVY_BINARY_PATH || 'trivy';
    private readonly defaultCacheDir = process.env.TRIVY_CACHE_DIR || path.resolve(process.cwd(), '..', '..', 'trivy-db');

    constructor(private readonly settingsService: SettingsService) { }

    async scanUploadedFile(filePath: string): Promise<any> {
        const uploadDir = path.dirname(filePath);

        try {
            if (!fs.existsSync(filePath)) {
                throw new BadRequestException('Uploaded file was not found');
            }

            const settings = await this.getTrivySettings();
            const args = this.buildTrivyArgs(settings, uploadDir);
            const timeoutMs = this.parseTimeoutMs(settings.timeout);

            const { stdout } = await execFileAsync(this.trivyBinary, args, {
                timeout: timeoutMs,
                maxBuffer: 100 * 1024 * 1024,
            });

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

    private buildTrivyArgs(settings: TrivySettings, targetPath: string): string[] {
        const severities = settings.severities?.length
            ? settings.severities.join(',')
            : 'CRITICAL,HIGH,MEDIUM,LOW';
        const scanners = settings.scanners?.length
            ? settings.scanners.map((scanner) => scanner === 'config' ? 'misconfig' : scanner).join(',')
            : 'vuln,secret,misconfig';

        const args = [
            'fs',
            '--format',
            'json',
            '--cache-dir',
            settings.cacheDir,
            '--skip-db-update',
            '--skip-java-db-update',
            '--severity',
            severities,
            '--scanners',
            scanners,
            '--timeout',
            settings.timeout || '10m',
        ];

        if (settings.ignoreUnfixed) {
            args.push('--ignore-unfixed');
        }

        args.push(targetPath);
        return args;
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
