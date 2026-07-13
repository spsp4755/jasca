import { BadRequestException, Injectable, Logger, RequestTimeoutException } from '@nestjs/common';
import { SettingsService } from '../../settings/settings.service';
import { ZapClientOptions, ZapClientService } from './zap-client.service';
import { ZapPolicyService, ZapSettings } from './zap-policy.service';

export interface ZapScanOptions {
    targetUrl: string;
    scanMode?: 'baseline' | 'passive' | 'active';
    authentication?: ZapScanAuthentication;
    targetProfileId?: string;
}

export interface ZapScanAuthentication {
    type?: 'none' | 'cookie' | 'authorization';
    value?: string;
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
        const operationKey = operationId || `internal-${startedAt}-${Math.random().toString(16).slice(2)}`;
        const settings = await this.getSettings();
        const scanMode = options.scanMode || 'baseline';
        if (scanMode === 'active') {
            throw new BadRequestException('JASCA currently supports Passive Spider Scan only.');
        }
        const profile = this.policyService.getTargetProfile(settings, options.targetProfileId);
        const target = this.policyService.validateTargetUrl(options.targetUrl, settings, profile.id);
        const authentication = this.normalizeAuthentication(options.authentication);

        if (!settings.allowBaselineScan) {
            throw new BadRequestException('ZAP Baseline Scan is disabled by administrator settings.');
        }

        if (this.activeScans.size >= settings.maxConcurrentScans) {
            throw new BadRequestException(`ZAP scan concurrency limit reached (${settings.maxConcurrentScans}). Try again after the current scan completes.`);
        }

        const clientOptions: ZapClientOptions = {
            baseUrl: settings.zapBaseUrl,
            apiKey: settings.apiKey,
            timeoutMs: settings.connectTimeoutSeconds * 1000,
        };
        const timeoutMs = Math.min(settings.maxScanDurationMinutes, profile.maxScanDurationMinutes) * 60 * 1000;
        const authRuleNames: string[] = [];

        this.activeScans.set(operationKey, { cancelled: false });

        try {
            const zapVersion = await this.zapClient.getVersion(clientOptions);
            this.throwIfCancelled(operationKey);

            for (const header of this.buildAuthenticationHeaders(authentication)) {
                const ruleName = this.buildRuleName(operationKey, header.kind);
                await this.zapClient.addRequestHeaderRule(clientOptions, ruleName, header.name, header.value);
                authRuleNames.push(ruleName);
            }
            this.throwIfCancelled(operationKey);

            const spiderScanId = await this.zapClient.spiderScan(clientOptions, target.href);
            this.activeScans.set(operationKey, { scanId: spiderScanId, cancelled: false });

            await this.waitForSpider(clientOptions, spiderScanId, timeoutMs, operationKey);
            this.throwIfCancelled(operationKey);

            const alerts = await this.zapClient.alerts(clientOptions, target.href);
            this.throwIfCancelled(operationKey);

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
                        targetProfile: { id: profile.id, name: profile.name },
                        scanMode,
                        zapVersion,
                        startedAt: new Date(startedAt).toISOString(),
                        completedAt: new Date().toISOString(),
                        durationMs: Date.now() - startedAt,
                        authentication: authentication.type === 'none' ? undefined : {
                            type: authentication.type,
                            requestHeaders: this.buildAuthenticationHeaders(authentication).map((header) => header.name),
                        },
                        options: {
                            maxScanDurationMinutes: timeoutMs / 60_000,
                            scanType: 'passive-spider',
                        },
                    },
                },
            };
        } finally {
            await Promise.all(authRuleNames.map((ruleName) => this.zapClient.removeRule(clientOptions, ruleName).catch((error) => {
                this.logger.warn(`Failed to remove ZAP auth rule ${ruleName}: ${(error as Error).message}`);
            })));
            this.activeScans.delete(operationKey);
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

    async testConnection(): Promise<{ connected: true; version: string }> {
        const settings = await this.getSettings();
        const version = await this.zapClient.getVersion({
            baseUrl: settings.zapBaseUrl,
            apiKey: settings.apiKey,
            timeoutMs: settings.connectTimeoutSeconds * 1000,
        });
        return { connected: true, version };
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

    private normalizeAuthentication(authentication?: ZapScanAuthentication): Required<ZapScanAuthentication> {
        const type = authentication?.type || 'none';
        const value = authentication?.value?.trim() || '';

        if (type === 'none') {
            return { type: 'none', value: '' };
        }

        if (!['cookie', 'authorization'].includes(type)) {
            throw new BadRequestException('Unsupported ZAP authentication type.');
        }

        if (!value) {
            throw new BadRequestException(`ZAP ${type} authentication value is required.`);
        }

        if (value.length > 16 * 1024 || /[\r\n]/.test(value)) {
            throw new BadRequestException('ZAP authentication value is invalid.');
        }

        return { type, value };
    }

    private buildAuthenticationHeaders(authentication: Required<ZapScanAuthentication>): Array<{ kind: string; name: string; value: string }> {
        if (authentication.type === 'cookie') {
            return [{ kind: 'cookie', name: 'Cookie', value: authentication.value }];
        }

        if (authentication.type === 'authorization') {
            return [{ kind: 'authorization', name: 'Authorization', value: authentication.value }];
        }

        return [];
    }

    private buildRuleName(operationId: string | undefined, kind: string): string {
        const id = (operationId || `${Date.now()}-${Math.random().toString(16).slice(2)}`)
            .replace(/[^a-zA-Z0-9._-]/g, '-')
            .slice(0, 80);
        return `jasca-auth-${id}-${kind}`;
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
            targetProfiles: [],
        };

        const store = this.settingsService as SettingsService & { getRaw?: (key: string) => Promise<unknown> };
        const stored = store.getRaw
            ? await store.getRaw('zap') as Partial<ZapSettings> | null
            : await this.settingsService.get('zap') as Partial<ZapSettings> | null;

        const resolved = { ...defaults, ...(stored || {}) };
        if (resolved.targetProfiles.length === 0 && resolved.allowedTargetPatterns.length > 0) {
            resolved.targetProfiles = [{
                id: 'legacy-default',
                name: '기본 대상 프로필',
                enabled: true,
                allowedTargetPatterns: resolved.allowedTargetPatterns,
                blockedTargetPatterns: resolved.blockedTargetPatterns,
                maxScanDurationMinutes: resolved.maxScanDurationMinutes,
                defaultRiskThresholdForNotification: resolved.defaultRiskThresholdForNotification,
            }];
        }
        return resolved;
    }
}
