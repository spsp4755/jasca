import { BadRequestException, Injectable, Logger, RequestTimeoutException, ServiceUnavailableException } from '@nestjs/common';
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
    scanMode?: 'auto' | 'fs' | 'rootfs' | 'image' | 'repo' | 'sbom' | 'vm' | 'rpm';
    analysisStrategy?: 'auto' | 'direct' | 'syft-sbom';
    rpmOsFamily?: string;
    rpmOsVersion?: string;
    offlineScan?: boolean;
    skipDbUpdate?: boolean;
    skipJavaDbUpdate?: boolean;
    ignoreUnfixed?: boolean;
    severities?: string[];
    scanners?: string[];
    timeout?: string;
}

type ArchiveType = 'zip' | 'tar' | 'tar.gz';
type TrivyScanMode = 'fs' | 'rootfs' | 'image' | 'repo' | 'sbom' | 'vm' | 'rpm';

interface PreparedScanTarget {
    mode: TrivyScanMode;
    targetPath: string;
    archiveType?: ArchiveType | null;
}

interface TrivyExecutionEvidence {
    executedBy: 'jasca';
    completed: true;
    startedAt: string;
    completedAt: string;
    durationMs: number;
    originalFileName: string;
    fileSizeBytes: number;
    scanMode: TrivyScanMode;
    archiveType?: ArchiveType | null;
    targetKind: string;
    cacheDir: string;
    options: {
        scanners: string[];
        severities: string[];
        offlineScan: boolean;
        skipDbUpdate: boolean;
        skipJavaDbUpdate: boolean;
        ignoreUnfixed: boolean;
        timeout: string;
        analysisStrategy?: string;
        rpmOsFamily?: string;
        rpmOsVersion?: string;
    };
    commands: Array<{
        phase: string;
        command: string;
    }>;
    resultSummary: {
        resultCount: number;
        targets: Array<{
            target: string;
            class?: string;
            type?: string;
            vulnerabilities: number;
            packages: number;
            licenses: number;
            misconfigurations: number;
            secrets: number;
        }>;
        vulnerabilities: number;
        packages: number;
        licenses: number;
        misconfigurations: number;
        secrets: number;
    };
}

@Injectable()
export class TrivyScanService {
    private readonly logger = new Logger(TrivyScanService.name);
    private readonly uploadRoot = path.join(os.tmpdir(), 'jasca-trivy-uploads');
    private readonly trivyBinary = process.env.TRIVY_BINARY_PATH || 'trivy';
    private readonly syftBinary = process.env.SYFT_BINARY_PATH || 'syft';
    private readonly defaultCacheDir = process.env.TRIVY_CACHE_DIR || path.resolve(process.cwd(), '..', '..', 'trivy-db');
    private readonly archiveMaxEntries = Number(process.env.TRIVY_ARCHIVE_MAX_ENTRIES || DEFAULT_ARCHIVE_MAX_ENTRIES);
    private readonly cancellationTtlMs = Number(process.env.TRIVY_CANCEL_TTL_MS || 2 * 60 * 60 * 1000);
    private readonly activeScans = new Map<string, { cancel: () => void; startedAt: number }>();
    private readonly cancelledScans = new Map<string, number>();
    private readonly savedScanResults = new Map<string, { scanId: string; savedAt: number }>();

    constructor(private readonly settingsService: SettingsService) { }

    async scanUploadedFile(filePath: string, options: TrivyScanOptions = {}, operationId?: string): Promise<any> {
        const uploadDir = path.dirname(filePath);

        try {
            if (!fs.existsSync(filePath)) {
                throw new BadRequestException('Uploaded file was not found');
            }

            this.assertNotCancelled(operationId);

            const startedAt = Date.now();
            const startedAtIso = new Date(startedAt).toISOString();
            const fileStats = fs.statSync(filePath);
            const settings = await this.getTrivySettings();
            const normalizedOptions = this.normalizeScanOptions(options);
            const scanTarget = await this.prepareScanTarget(filePath, uploadDir, normalizedOptions);
            const effectiveTimeout = normalizedOptions.timeout || settings.timeout;
            const timeoutMs = this.parseTimeoutMs(effectiveTimeout);
            this.logger.log(`Trivy scan prepared. operationId=${operationId || 'n/a'} mode=${scanTarget.mode} file=${path.basename(filePath)} size=${fileStats.size}B prepareMs=${Date.now() - startedAt}`);

            const commands: TrivyExecutionEvidence['commands'] = [];
            const stdout = scanTarget.mode === 'rpm'
                ? await this.runRpmArchiveScan(settings, scanTarget, normalizedOptions, timeoutMs, operationId, commands)
                : await this.runScanWithStrategy(settings, scanTarget, normalizedOptions, timeoutMs, operationId, commands);

            this.assertNotCancelled(operationId);
            const completedAt = Date.now();
            this.logger.log(`Trivy scan completed. operationId=${operationId || 'n/a'} mode=${scanTarget.mode} durationMs=${completedAt - startedAt}`);

            const result = JSON.parse(stdout);
            this.attachExecutionEvidence(result, {
                executedBy: 'jasca',
                completed: true,
                startedAt: startedAtIso,
                completedAt: new Date(completedAt).toISOString(),
                durationMs: completedAt - startedAt,
                originalFileName: path.basename(filePath),
                fileSizeBytes: fileStats.size,
                scanMode: scanTarget.mode,
                archiveType: scanTarget.archiveType,
                targetKind: this.getTargetKind(scanTarget),
                cacheDir: settings.cacheDir,
                options: {
                    scanners: this.effectiveScanners(settings, normalizedOptions),
                    severities: this.effectiveSeverities(settings, normalizedOptions),
                    offlineScan: normalizedOptions.offlineScan === true,
                    skipDbUpdate: normalizedOptions.skipDbUpdate !== false,
                    skipJavaDbUpdate: normalizedOptions.skipJavaDbUpdate !== false,
                    ignoreUnfixed: normalizedOptions.ignoreUnfixed ?? settings.ignoreUnfixed,
                    timeout: effectiveTimeout,
                    analysisStrategy: normalizedOptions.analysisStrategy || 'auto',
                    rpmOsFamily: normalizedOptions.rpmOsFamily,
                    rpmOsVersion: normalizedOptions.rpmOsVersion,
                },
                commands,
                resultSummary: this.summarizeTrivyResult(result),
            });

            return result;
        } catch (error) {
            const stdout = (error as any)?.stdout;
            if (stdout) {
                try {
                    return JSON.parse(stdout);
                } catch {
                    // Fall through to a readable error below.
                }
            }

            if (error instanceof BadRequestException || error instanceof RequestTimeoutException) {
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
        this.cleanupExpiredCancellations();
        this.cancelledScans.set(operationId, Date.now());

        const activeScan = this.activeScans.get(operationId);
        if (!activeScan) {
            this.logger.warn(`Trivy scan cancellation registered before process start. operationId=${operationId}`);
            return true;
        }

        activeScan.cancel();
        return true;
    }

    isCancellationRequested(operationId?: string): boolean {
        this.cleanupExpiredCancellations();
        return !!operationId && this.cancelledScans.has(operationId);
    }

    markScanSaved(operationId: string | undefined, scanId: string): void {
        if (!operationId) return;
        this.cleanupExpiredCancellations();
        this.savedScanResults.set(operationId, { scanId, savedAt: Date.now() });
    }

    consumeSavedScan(operationId: string): string | undefined {
        this.cleanupExpiredCancellations();
        const saved = this.savedScanResults.get(operationId);
        if (!saved) return undefined;
        this.savedScanResults.delete(operationId);
        return saved.scanId;
    }

    private assertNotCancelled(operationId?: string): void {
        if (this.isCancellationRequested(operationId)) {
            throw new BadRequestException('Trivy scan was cancelled by the user');
        }
    }

    private cleanupExpiredCancellations(): void {
        const now = Date.now();
        for (const [operationId, requestedAt] of this.cancelledScans.entries()) {
            if (now - requestedAt > this.cancellationTtlMs) {
                this.cancelledScans.delete(operationId);
            }
        }
        for (const [operationId, saved] of this.savedScanResults.entries()) {
            if (now - saved.savedAt > this.cancellationTtlMs) {
                this.savedScanResults.delete(operationId);
            }
        }
    }

    private runTrivy(args: string[], timeoutMs: number, operationId?: string, extraEnv: NodeJS.ProcessEnv = {}): Promise<string> {
        return new Promise((resolve, reject) => {
            if (this.isCancellationRequested(operationId)) {
                reject(new BadRequestException('Trivy scan was cancelled by the user'));
                return;
            }

            const child = spawn(this.trivyBinary, args, {
                env: { ...process.env, ...extraEnv },
                stdio: ['ignore', 'pipe', 'pipe'],
            });
            const stdoutChunks: Buffer[] = [];
            const stderrChunks: Buffer[] = [];
            let cancelledByUser = false;
            let timedOut = false;
            let outputLimitExceeded = false;
            let killTimer: NodeJS.Timeout | undefined;
            let settled = false;

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
                this.activeScans.set(operationId, {
                    startedAt: Date.now(),
                    cancel: () => {
                        cancelledByUser = true;
                        this.logger.warn(`Trivy scan cancellation requested by user. operationId=${operationId}`);
                        terminate();
                    },
                });
            }

            child.stdout.on('data', (chunk: Buffer) => {
                stdoutChunks.push(chunk);
                if (Buffer.concat(stdoutChunks).length > 100 * 1024 * 1024) {
                    outputLimitExceeded = true;
                    terminate();
                }
            });

            child.stderr.on('data', (chunk: Buffer) => {
                stderrChunks.push(chunk);
            });

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
                    reject(new BadRequestException('Trivy scan was cancelled by the user'));
                    return;
                }

                if (timedOut) {
                    reject(new RequestTimeoutException(`Trivy scan timed out after ${timeoutMs}ms`));
                    return;
                }

                if (outputLimitExceeded) {
                    reject(new Error('Trivy output exceeded the 100MB limit'));
                    return;
                }

                if (code !== 0) {
                    const exitDetail = signal
                        ? `Trivy exited with signal ${signal}`
                        : `Trivy exited with code ${code}`;
                    const error = new Error(exitDetail);
                    (error as any).stdout = stdout;
                    (error as any).stderr = stderr;
                    reject(error);
                    return;
                }

                resolve(stdout);
            });
        });
    }

    private async runScanWithStrategy(
        settings: TrivySettings,
        target: PreparedScanTarget,
        options: TrivyScanOptions,
        timeoutMs: number,
        operationId: string | undefined,
        commands: TrivyExecutionEvidence['commands'],
    ): Promise<string> {
        const strategy = options.analysisStrategy || 'auto';
        const supportsSyft = ['fs', 'rootfs', 'repo'].includes(target.mode);

        if (strategy === 'syft-sbom') {
            if (!supportsSyft) {
                throw new BadRequestException('Syft SBOM strategy supports fs, rootfs, and repo scan modes only.');
            }
            return this.runSyftThenTrivySbom(settings, target, options, timeoutMs, operationId, commands);
        }

        const directOutput = await this.runTrivy(
            this.trackCommand(commands, 'trivy-direct-scan', this.buildTrivyArgs(settings, target, options), target),
            timeoutMs,
            operationId,
        );

        if (strategy === 'direct' || !supportsSyft || !this.shouldFallbackToSyft(directOutput)) {
            return directOutput;
        }

        this.logger.warn(`Trivy direct scan produced weak inventory. Falling back to Syft SBOM. mode=${target.mode} target=${path.basename(target.targetPath)}`);
        return this.runSyftThenTrivySbom(settings, target, options, timeoutMs, operationId, commands);
    }

    private shouldFallbackToSyft(stdout: string): boolean {
        try {
            const summary = this.summarizeTrivyResult(JSON.parse(stdout));
            return summary.resultCount === 0 || summary.packages === 0;
        } catch {
            return false;
        }
    }

    private async runSyftThenTrivySbom(
        settings: TrivySettings,
        target: PreparedScanTarget,
        options: TrivyScanOptions,
        timeoutMs: number,
        operationId: string | undefined,
        commands: TrivyExecutionEvidence['commands'],
    ): Promise<string> {
        const sbomPath = path.join(path.dirname(target.targetPath), `syft-${Date.now()}.cdx.json`);
        const syftArgs = [target.targetPath, '-o', 'cyclonedx-json'];
        const sbom = await this.runSyft(this.trackSyftCommand(commands, 'syft-sbom', syftArgs, target), timeoutMs, operationId);
        await fs.promises.writeFile(sbomPath, sbom, 'utf-8');

        this.assertNotCancelled(operationId);
        const sbomScanOptions: TrivyScanOptions = {
            ...options,
            analysisStrategy: 'direct',
            scanners: options.scanners?.filter((scanner) => ['vuln', 'license'].includes(scanner)),
        };
        const sbomArgs = this.buildTrivyArgs(settings, { ...target, mode: 'sbom', targetPath: sbomPath }, sbomScanOptions);
        return this.runTrivy(
            this.trackCommand(commands, 'trivy-syft-sbom-scan', sbomArgs, { ...target, mode: 'sbom', targetPath: sbomPath }),
            timeoutMs,
            operationId,
        );
    }

    private runSyft(args: string[], timeoutMs: number, operationId?: string): Promise<string> {
        return new Promise((resolve, reject) => {
            if (this.isCancellationRequested(operationId)) {
                reject(new BadRequestException('Trivy scan was cancelled by the user'));
                return;
            }

            const child = spawn(this.syftBinary, args, {
                env: { ...process.env },
                stdio: ['ignore', 'pipe', 'pipe'],
            });
            const stdoutChunks: Buffer[] = [];
            const stderrChunks: Buffer[] = [];
            let cancelledByUser = false;
            let timedOut = false;
            let outputLimitExceeded = false;
            let killTimer: NodeJS.Timeout | undefined;
            let settled = false;

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
                this.activeScans.set(operationId, {
                    startedAt: Date.now(),
                    cancel: () => {
                        cancelledByUser = true;
                        this.logger.warn(`Syft SBOM generation cancellation requested by user. operationId=${operationId}`);
                        terminate();
                    },
                });
            }

            child.stdout.on('data', (chunk: Buffer) => {
                stdoutChunks.push(chunk);
                if (Buffer.concat(stdoutChunks).length > 100 * 1024 * 1024) {
                    outputLimitExceeded = true;
                    terminate();
                }
            });

            child.stderr.on('data', (chunk: Buffer) => {
                stderrChunks.push(chunk);
            });

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
                    reject(new BadRequestException('Trivy scan was cancelled by the user'));
                    return;
                }
                if (timedOut) {
                    reject(new RequestTimeoutException(`Syft SBOM generation timed out after ${timeoutMs}ms`));
                    return;
                }
                if (outputLimitExceeded) {
                    reject(new Error('Syft output exceeded the 100MB limit'));
                    return;
                }
                if (code !== 0) {
                    const exitDetail = signal ? `Syft exited with signal ${signal}` : `Syft exited with code ${code}`;
                    const error = new Error(`${exitDetail}: ${stderr || stdout}`);
                    (error as any).stdout = stdout;
                    (error as any).stderr = stderr;
                    reject(error);
                    return;
                }

                resolve(stdout);
            });
        });
    }

    private async prepareScanTarget(filePath: string, uploadDir: string, options: TrivyScanOptions): Promise<PreparedScanTarget> {
        const archiveType = this.detectArchiveType(filePath);
        const requestedMode = options.scanMode || 'auto';
        const lowerName = path.basename(filePath).toLowerCase();

        if (requestedMode === 'rpm' || (requestedMode === 'auto' && lowerName.endsWith('.rpm'))) {
            if (!lowerName.endsWith('.rpm')) {
                throw new BadRequestException('RPM archive scan requires a .rpm file.');
            }

            return { mode: 'rpm', targetPath: filePath, archiveType: null };
        }

        if (requestedMode === 'sbom') {
            return { mode: 'sbom', targetPath: filePath, archiveType: archiveType };
        }

        if (requestedMode === 'vm') {
            if (archiveType) {
                throw new BadRequestException('VM image scan requires a VM image file such as qcow2, vmdk, vhd, or raw img, not a compressed archive.');
            }

            return { mode: 'vm', targetPath: filePath, archiveType: null };
        }

        if (requestedMode === 'image') {
            if (!archiveType || archiveType === 'zip') {
                throw new BadRequestException('Image archive scan requires a Docker/OCI tar or tar.gz file.');
            }

            const entries = await this.listArchiveEntries(filePath, archiveType);
            if (!this.looksLikeContainerImageArchive(entries)) {
                throw new BadRequestException('The uploaded archive does not look like a Docker or OCI image archive.');
            }

            return { mode: 'image', targetPath: filePath, archiveType };
        }

        if (!archiveType) {
            if (requestedMode === 'repo') {
                throw new BadRequestException('Repository scan requires an uploaded source archive such as .zip, .tar, or .tar.gz.');
            }

            return {
                mode: requestedMode === 'rootfs' ? 'rootfs' : 'fs',
                targetPath: this.shouldScanSingleFile(filePath) ? filePath : uploadDir,
                archiveType: null,
            };
        }

        const entries = await this.validateArchiveEntries(filePath, archiveType);
        if (requestedMode === 'auto' && this.looksLikeContainerImageArchive(entries)) {
            return { mode: 'image', targetPath: filePath, archiveType };
        }

        const extractDir = path.join(uploadDir, 'extracted');
        fs.mkdirSync(extractDir, { recursive: true });

        await this.extractArchive(filePath, archiveType, extractDir);

        const mode: TrivyScanMode = requestedMode === 'rootfs' || (requestedMode === 'auto' && this.looksLikeRootfs(extractDir))
            ? 'rootfs'
            : requestedMode === 'repo'
                ? 'repo'
            : 'fs';

        return { mode, targetPath: extractDir, archiveType };
    }

    private async runRpmArchiveScan(
        settings: TrivySettings,
        target: PreparedScanTarget,
        options: TrivyScanOptions,
        timeoutMs: number,
        operationId?: string,
        commands: TrivyExecutionEvidence['commands'] = [],
    ): Promise<string> {
        const sbomPath = path.join(path.dirname(target.targetPath), 'rpm-sbom.cdx.json');
        const sbomArgs = [
            'fs',
            '--format',
            'cyclonedx',
            '--output',
            sbomPath,
            '--scanners',
            'vuln',
            target.targetPath,
        ];

        const rpmStartedAt = Date.now();
        this.logger.log(`Generating RPM SBOM. operationId=${operationId || 'n/a'} file=${path.basename(target.targetPath)}`);
        await this.runTrivy(this.trackCommand(commands, 'rpm-sbom', sbomArgs, target), timeoutMs, operationId, {
            TRIVY_EXPERIMENTAL_RPM_ARCHIVE: 'true',
        });

        this.assertNotCancelled(operationId);
        await this.ensureRpmSbomComponents(sbomPath, target.targetPath, options);
        this.logger.log(`RPM SBOM generated. operationId=${operationId || 'n/a'} durationMs=${Date.now() - rpmStartedAt}`);

        const sbomScanOptions: TrivyScanOptions = {
            ...options,
            scanners: options.scanners?.filter((scanner) => ['vuln', 'license'].includes(scanner)),
        };
        const sbomScanArgs = this.buildTrivyArgs(settings, { ...target, mode: 'fs', targetPath: sbomPath }, sbomScanOptions);
        sbomScanArgs[0] = 'sbom';
        sbomScanArgs.splice(sbomScanArgs.length - 1, 1, sbomPath);

        return this.runTrivy(this.trackCommand(commands, 'rpm-vuln-scan', sbomScanArgs, { ...target, targetPath: sbomPath }), timeoutMs, operationId);
    }

    private trackCommand(
        commands: TrivyExecutionEvidence['commands'],
        phase: string,
        args: string[],
        target: PreparedScanTarget,
    ): string[] {
        commands.push({
            phase,
            command: [this.trivyBinary, ...this.redactCommandArgs(args, target)].join(' '),
        });
        return args;
    }

    private trackSyftCommand(
        commands: TrivyExecutionEvidence['commands'],
        phase: string,
        args: string[],
        target: PreparedScanTarget,
    ): string[] {
        commands.push({
            phase,
            command: [this.syftBinary, ...this.redactCommandArgs(args, target)].join(' '),
        });
        return args;
    }

    private redactCommandArgs(args: string[], target: PreparedScanTarget): string[] {
        const targetPath = path.resolve(target.targetPath);
        const uploadDir = path.dirname(targetPath);
        return args.map((arg) => {
            const resolved = path.resolve(arg);
            if (resolved === targetPath) {
                return `<upload:${path.basename(targetPath)}>`;
            }
            if (resolved === uploadDir) {
                return '<upload-dir>';
            }
            if (resolved.startsWith(uploadDir + path.sep)) {
                return `<upload:${path.basename(arg)}>`;
            }
            return /\s/.test(arg) ? JSON.stringify(arg) : arg;
        });
    }

    private attachExecutionEvidence(result: any, evidence: TrivyExecutionEvidence): void {
        result.Metadata = result.Metadata || {};
        result.Metadata.JascaScanEvidence = evidence;
    }

    private summarizeTrivyResult(result: any): TrivyExecutionEvidence['resultSummary'] {
        const results = Array.isArray(result?.Results) ? result.Results : [];
        const targets: TrivyExecutionEvidence['resultSummary']['targets'] = results.map((target: any) => {
            const packages = Array.isArray(target.Packages) ? target.Packages : [];
            return {
                target: target.Target || 'unknown',
                class: target.Class,
                type: target.Type,
                vulnerabilities: Array.isArray(target.Vulnerabilities) ? target.Vulnerabilities.length : 0,
                packages: packages.length,
                licenses: packages.reduce((sum: number, pkg: any) => sum + (Array.isArray(pkg.Licenses) ? pkg.Licenses.length : 0), 0),
                misconfigurations: Array.isArray(target.Misconfigurations) ? target.Misconfigurations.length : 0,
                secrets: Array.isArray(target.Secrets) ? target.Secrets.length : 0,
            };
        });

        return {
            resultCount: results.length,
            targets,
            vulnerabilities: targets.reduce((sum: number, target) => sum + target.vulnerabilities, 0),
            packages: targets.reduce((sum: number, target) => sum + target.packages, 0),
            licenses: targets.reduce((sum: number, target) => sum + target.licenses, 0),
            misconfigurations: targets.reduce((sum: number, target) => sum + target.misconfigurations, 0),
            secrets: targets.reduce((sum: number, target) => sum + target.secrets, 0),
        };
    }

    private effectiveScanners(settings: TrivySettings, options: TrivyScanOptions): string[] {
        const scanners = options.scanners?.length ? options.scanners : settings.scanners;
        return (scanners?.length ? scanners : ['vuln', 'license'])
            .map((scanner) => scanner === 'config' ? 'misconfig' : scanner);
    }

    private effectiveSeverities(settings: TrivySettings, options: TrivyScanOptions): string[] {
        return options.severities?.length
            ? options.severities
            : settings.severities?.length
                ? settings.severities
                : ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    }

    private async ensureRpmSbomComponents(sbomPath: string, rpmPath: string, options: TrivyScanOptions): Promise<void> {
        const osFamily = (options.rpmOsFamily || process.env.TRIVY_RPM_OS_FAMILY || 'redhat').trim();
        const osVersion = (options.rpmOsVersion || process.env.TRIVY_RPM_OS_VERSION || '').trim();

        if (!osVersion) {
            this.logger.warn('RPM scan is missing OS version. Set rpmOsVersion in UI or TRIVY_RPM_OS_VERSION for accurate vulnerability matching.');
        }

        const sbom = JSON.parse(await fs.promises.readFile(sbomPath, 'utf-8'));
        sbom.components = Array.isArray(sbom.components) ? sbom.components : [];

        const existingOs = sbom.components.find((component: any) => component?.type === 'operating-system');
        if (existingOs) {
            existingOs.name = existingOs.name || osFamily;
            existingOs.version = existingOs.version || osVersion;
        } else {
            sbom.components.unshift({
                type: 'operating-system',
                name: osFamily,
                version: osVersion,
            });
        }

        const hasPackageComponent = sbom.components.some((component: any) =>
            component?.type !== 'operating-system' && (component?.purl || component?.name),
        );

        if (!hasPackageComponent) {
            const rpm = await this.queryRpmMetadata(rpmPath);
            const namespace = osFamily.toLowerCase();
            const distro = osVersion ? `${namespace}-${osVersion}` : namespace;
            const versionWithRelease = rpm.release ? `${rpm.version}-${rpm.release}` : rpm.version;
            sbom.components.push({
                type: 'library',
                name: rpm.name,
                version: versionWithRelease,
                purl: `pkg:rpm/${namespace}/${rpm.name}@${versionWithRelease}?arch=${rpm.arch}&distro=${distro}`,
            });
            this.logger.log(`RPM SBOM component injected. package=${rpm.name} version=${versionWithRelease} arch=${rpm.arch} os=${distro}`);
        }

        await fs.promises.writeFile(sbomPath, JSON.stringify(sbom), 'utf-8');
    }

    private async queryRpmMetadata(rpmPath: string): Promise<{ name: string; version: string; release: string; arch: string }> {
        try {
            const { stdout } = await execFileAsync('rpm', ['-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', rpmPath], {
                timeout: 30 * 1000,
                maxBuffer: 1024 * 1024,
            });
            const [name, version, release, arch] = stdout.trim().split('\t');
            if (!name || !version || !arch) {
                throw new Error(`Unexpected rpm metadata output: ${stdout}`);
            }

            return {
                name,
                version,
                release: release || '',
                arch,
            };
        } catch (error) {
            this.logger.warn(`Failed to query RPM metadata for ${path.basename(rpmPath)}: ${(error as Error).message}`);
            throw new BadRequestException('RPM metadata could not be read. Ensure the file is a valid RPM package.');
        }
    }

    private detectArchiveType(filePath: string): ArchiveType | null {
        const lowerName = path.basename(filePath).toLowerCase();
        if (lowerName.endsWith('.zip')) return 'zip';
        if (lowerName.endsWith('.tar.gz') || lowerName.endsWith('.tgz')) return 'tar.gz';
        if (lowerName.endsWith('.tar')) return 'tar';
        return null;
    }

    private async validateArchiveEntries(filePath: string, archiveType: ArchiveType): Promise<string[]> {
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

        return entries;
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

    private looksLikeContainerImageArchive(entries: string[]): boolean {
        const normalized = entries.map((entry) => entry.replace(/\\/g, '/'));
        return normalized.some((entry) => entry === 'manifest.json' || entry.endsWith('/manifest.json')) ||
            normalized.some((entry) => entry === 'oci-layout' || entry.endsWith('/oci-layout')) ||
            normalized.some((entry) => entry === 'repositories' || entry.endsWith('/repositories')) ||
            normalized.some((entry) => entry.endsWith('/blobs/sha256/')) ||
            normalized.some((entry) => /^blobs\/sha256\/[a-f0-9]{64}$/i.test(entry));
    }

    private looksLikeRootfs(rootPath: string): boolean {
        const indicators = [
            'etc/os-release',
            'usr/lib/os-release',
            'var/lib/dpkg/status',
            'var/lib/rpm',
            'usr/lib/sysimage/rpm',
            'lib/apk/db/installed',
            'var/lib/apk/db/installed',
        ];

        return indicators.some((indicator) => fs.existsSync(path.join(rootPath, indicator)));
    }

    private shouldScanSingleFile(filePath: string): boolean {
        const lowerName = path.basename(filePath).toLowerCase();
        return [
            '.rpm',
            '.deb',
            '.apk',
            '.jar',
            '.war',
            '.ear',
            '.gem',
            '.whl',
            '.egg',
            '.nupkg',
            '.lock',
            '.json',
            '.xml',
            '.yaml',
            '.yml',
            '.toml',
            '.gradle',
            '.csproj',
            '.sln',
        ].some((extension) => lowerName.endsWith(extension)) || lowerName === 'dockerfile';
    }

    private async getTrivySettings(): Promise<TrivySettings> {
        const defaults: TrivySettings = {
            outputFormat: 'json',
            schemaVersion: 2,
            severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            ignoreUnfixed: false,
            timeout: '10m',
            cacheDir: this.defaultCacheDir,
            scanners: ['vuln', 'license'],
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

    private buildTrivyArgs(settings: TrivySettings, target: PreparedScanTarget, options: TrivyScanOptions): string[] {
        const severities = options.severities?.length
            ? options.severities.join(',')
            : settings.severities?.length
                ? settings.severities.join(',')
                : 'CRITICAL,HIGH,MEDIUM,LOW';
        const scanners = options.scanners?.length
            ? options.scanners.join(',')
            : settings.scanners?.length
                ? settings.scanners.map((scanner) => scanner === 'config' ? 'misconfig' : scanner).join(',')
                : 'vuln,license';
        const timeout = options.timeout || settings.timeout || '10m';
        const skipDbUpdate = options.skipDbUpdate !== false;
        const skipJavaDbUpdate = options.skipJavaDbUpdate !== false;
        const ignoreUnfixed = options.ignoreUnfixed ?? settings.ignoreUnfixed;

        const args = [
            target.mode,
            '--format',
            'json',
            '--cache-dir',
            settings.cacheDir,
        ];

        if (target.mode === 'image') {
            args.push('--input', target.targetPath);
        }

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

        if (target.mode !== 'image') {
            args.push(target.targetPath);
        }
        return args;
    }

    private normalizeScanOptions(options: TrivyScanOptions): TrivyScanOptions {
        const allowedModes = new Set(['auto', 'fs', 'rootfs', 'image', 'repo', 'sbom', 'vm', 'rpm']);
        const allowedStrategies = new Set(['auto', 'direct', 'syft-sbom']);
        const allowedSeverities = new Set(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
        const allowedScanners = new Set(['vuln', 'license', 'secret', 'misconfig']);

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
            scanMode: allowedModes.has(options.scanMode || '') ? options.scanMode : 'auto',
            analysisStrategy: allowedStrategies.has(options.analysisStrategy || '') ? options.analysisStrategy : 'auto',
            rpmOsFamily: options.rpmOsFamily?.trim() || process.env.TRIVY_RPM_OS_FAMILY || 'redhat',
            rpmOsVersion: options.rpmOsVersion?.trim() || process.env.TRIVY_RPM_OS_VERSION || undefined,
            offlineScan: options.offlineScan === true,
            skipDbUpdate: options.skipDbUpdate !== false,
            skipJavaDbUpdate: options.skipJavaDbUpdate !== false,
            ignoreUnfixed: options.ignoreUnfixed === true,
            severities: severities?.length ? severities : undefined,
            scanners: scanners?.length ? scanners : undefined,
            timeout: timeout || undefined,
        };
    }

    private getTargetKind(target: PreparedScanTarget): string {
        if (target.mode === 'image') return 'container-image-archive';
        if (target.mode === 'repo') return 'source-repository-archive';
        if (target.mode === 'sbom') return 'sbom-file';
        if (target.mode === 'vm') return 'virtual-machine-image';
        if (target.mode === 'rpm') return 'rpm-helper-sbom-flow';
        if (target.archiveType) return 'extracted-archive';
        return 'uploaded-file';
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
