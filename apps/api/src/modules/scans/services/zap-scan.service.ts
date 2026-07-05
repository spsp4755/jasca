import { BadRequestException, Injectable, Logger, RequestTimeoutException } from '@nestjs/common';
import { SettingsService } from '../../settings/settings.service';
import { ZapClientOptions, ZapClientService } from './zap-client.service';
import { ZapPolicyService, ZapSettings } from './zap-policy.service';

export interface ZapScanOptions {
    targetUrl: string;
    scanMode?: 'baseline' | 'passive' | 'active';
}

@Injectable()
export class ZapScanService {
    private readonly logger = new Logger(ZapScanService.name);
    private readonly activeScans = new Map<string, { scanId?: string; cancelled: boolean }>();

    constructor(
        private readonly settingsService: SettingsService,
        private readonly policyService: ZapPolicyService,
        private readonly zapClient: ZapClientService,
    ) { }

    async scanUrl(options: ZapScanOptions, operationId?: string): Promise<any> {
        const startedAt = Date.now();
        const settings = await this.getSettings();
        const target = this.policyService.validateTargetUrl(options.targetUrl, settings);
        const scanMode = options.scanMode || 'baseline';

        if (scanMode === 'active' && !settings.allowActiveScan) {
            throw new BadRequestException('ZAP Active Scan is disabled by administrator settings.');
        }

        if (scanMode !== 'active' && !settings.allowBaselineScan) {
            throw new BadRequestException('ZAP Baseline Scan is disabled by administrator settings.');
        }

        const clientOptions: ZapClientOptions = {
            baseUrl: settings.zapBaseUrl,
            apiKey: settings.apiKey,
            timeoutMs: settings.connectTimeoutSeconds * 1000,
        };
        const timeoutMs = settings.maxScanDurationMinutes * 60 * 1000;

        if (operationId) {
            this.activeScans.set(operationId, { cancelled: false });
        }

        try {
            const zapVersion = await this.zapClient.getVersion(clientOptions);
            this.throwIfCancelled(operationId);

            const spiderScanId = await this.zapClient.spiderScan(clientOptions, target.href);
            if (operationId) {
                this.activeScans.set(operationId, { scanId: spiderScanId, cancelled: false });
            }

            await this.waitForSpider(clientOptions, spiderScanId, timeoutMs, operationId);
            this.throwIfCancelled(operationId);

            const alerts = await this.zapClient.alerts(clientOptions, target.href);
            this.throwIfCancelled(operationId);

            return {
                zapVersion,
                site: [
                    {
                        '@name': target.origin,
                        alerts,
                    },
                ],
                Metadata: {
                    JascaScanEvidence: {
                        executedBy: 'jasca',
                        scanner: 'zap',
                        completed: true,
                        targetUrl: target.href,
                        scanMode,
                        zapVersion,
                        startedAt: new Date(startedAt).toISOString(),
                        completedAt: new Date().toISOString(),
                        durationMs: Date.now() - startedAt,
                        options: {
                            maxScanDurationMinutes: settings.maxScanDurationMinutes,
                            allowActiveScan: settings.allowActiveScan,
                        },
                    },
                },
            };
        } finally {
            if (operationId) {
                this.activeScans.delete(operationId);
            }
        }
    }

    async cancelScan(operationId: string): Promise<boolean> {
        const active = this.activeScans.get(operationId);
        if (!active) {
            return false;
        }

        active.cancelled = true;
        this.activeScans.set(operationId, active);

        const settings = await this.getSettings();
        if (active.scanId) {
            await this.zapClient.stopSpider({
                baseUrl: settings.zapBaseUrl,
                apiKey: settings.apiKey,
                timeoutMs: settings.connectTimeoutSeconds * 1000,
            }, active.scanId).catch((error) => {
                this.logger.warn(`Failed to stop ZAP spider: ${(error as Error).message}`);
            });
        }

        return true;
    }

    private async waitForSpider(options: ZapClientOptions, scanId: string, timeoutMs: number, operationId?: string): Promise<void> {
        const deadline = Date.now() + timeoutMs;

        while (Date.now() < deadline) {
            this.throwIfCancelled(operationId);
            const status = await this.zapClient.spiderStatus(options, scanId);
            this.throwIfCancelled(operationId);

            if (status >= 100) {
                return;
            }

            await new Promise((resolve) => setTimeout(resolve, 2000));
        }

        throw new RequestTimeoutException(`ZAP scan timed out after ${timeoutMs}ms`);
    }

    private throwIfCancelled(operationId?: string): void {
        if (operationId && this.activeScans.get(operationId)?.cancelled) {
            throw new BadRequestException('ZAP scan was cancelled by the user');
        }
    }

    private async getSettings(): Promise<ZapSettings> {
        const defaults: ZapSettings = {
            enabled: false,
            zapBaseUrl: process.env.ZAP_BASE_URL || 'http://zap-scanner:8080',
            apiKey: process.env.ZAP_API_KEY || '',
            connectTimeoutSeconds: 10,
            maxScanDurationMinutes: 30,
            maxConcurrentScans: 1,
            allowBaselineScan: true,
            allowActiveScan: false,
            allowedTargetPatterns: [],
            blockedTargetPatterns: [],
            defaultRiskThresholdForNotification: 'HIGH',
        };

        const store = this.settingsService as SettingsService & { getRaw?: (key: string) => Promise<unknown> };
        const stored = store.getRaw
            ? await store.getRaw('zap') as Partial<ZapSettings> | null
            : await this.settingsService.get('zap') as Partial<ZapSettings> | null;

        return { ...defaults, ...(stored || {}) };
    }
}
