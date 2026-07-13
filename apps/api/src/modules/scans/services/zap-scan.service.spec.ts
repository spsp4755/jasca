import { BadRequestException } from '@nestjs/common';
import { ZapScanService } from './zap-scan.service';

describe('ZapScanService', () => {
    const settingsService = {
        get: jest.fn(),
        getRaw: jest.fn(),
    };
    const policyService = {
        validateTargetUrl: jest.fn(),
        getTargetProfile: jest.fn(),
    };
    const zapClient = {
        getVersion: jest.fn(),
        spiderScan: jest.fn(),
        spiderStatus: jest.fn(),
        alerts: jest.fn(),
        stopSpider: jest.fn(),
        addRequestHeaderRule: jest.fn(),
        removeRule: jest.fn(),
    };

    beforeEach(() => {
        jest.resetAllMocks();
        settingsService.getRaw.mockResolvedValue({
            enabled: true,
            zapBaseUrl: 'http://zap:8080',
            apiKey: 'key',
            connectTimeoutSeconds: 10,
            maxScanDurationMinutes: 1,
            maxConcurrentScans: 1,
            allowBaselineScan: true,
            allowActiveScan: false,
            allowedTargetPatterns: ['*.internal'],
            blockedTargetPatterns: [],
            defaultRiskThresholdForNotification: 'HIGH',
            targetProfiles: [{
                id: 'internal-app',
                name: 'Internal App',
                enabled: true,
                allowedTargetPatterns: ['*.internal'],
                blockedTargetPatterns: [],
                maxScanDurationMinutes: 1,
                defaultRiskThresholdForNotification: 'HIGH',
            }],
        });
        policyService.validateTargetUrl.mockReturnValue(new URL('https://demo.internal'));
        policyService.getTargetProfile.mockReturnValue({
            id: 'internal-app',
            name: 'Internal App',
            enabled: true,
            allowedTargetPatterns: ['*.internal'],
            blockedTargetPatterns: [],
            maxScanDurationMinutes: 1,
            defaultRiskThresholdForNotification: 'HIGH',
        });
        zapClient.getVersion.mockResolvedValue('2.15.0');
        zapClient.spiderScan.mockResolvedValue('1');
        zapClient.spiderStatus.mockResolvedValue(100);
        zapClient.stopSpider.mockResolvedValue(undefined);
        zapClient.addRequestHeaderRule.mockResolvedValue(undefined);
        zapClient.removeRule.mockResolvedValue(undefined);
        zapClient.alerts.mockResolvedValue([
            {
                pluginid: '10038',
                alert: 'Content Security Policy Header Not Set',
                riskdesc: 'Medium (High)',
                confidence: 'High',
                instances: [{ uri: 'https://demo.internal', method: 'GET', evidence: 'Missing CSP' }],
            },
        ]);
    });

    it('runs a baseline ZAP scan and returns ZAP-shaped JSON', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        const result = await service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline', targetProfileId: 'internal-app' } as any, 'op-1');

        expect(policyService.validateTargetUrl).toHaveBeenCalledWith('https://demo.internal', expect.objectContaining({
            enabled: true,
            apiKey: 'key',
        }), 'internal-app');
        expect(zapClient.spiderScan).toHaveBeenCalledWith(expect.objectContaining({
            baseUrl: 'http://zap:8080',
            apiKey: 'key',
            timeoutMs: 10000,
        }), 'https://demo.internal/');
        expect(result.site[0].alerts).toHaveLength(1);
        expect(result.Metadata.JascaScanEvidence).toEqual(expect.objectContaining({
            scanner: 'zap',
            targetUrl: 'https://demo.internal/',
            scanMode: 'baseline',
            zapVersion: '2.15.0',
            targetProfile: { id: 'internal-app', name: 'Internal App' },
        }));
    });

    it('tests the configured ZAP server with the version endpoint only', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);

        await expect((service as any).testConnection()).resolves.toEqual({ connected: true, version: '2.15.0' });
        expect(zapClient.getVersion).toHaveBeenCalledWith(expect.objectContaining({
            baseUrl: 'http://zap:8080',
            apiKey: 'key',
            timeoutMs: 10000,
        }));
        expect(zapClient.spiderScan).not.toHaveBeenCalled();
    });

    it('provides a default target profile for existing allowlist-only settings', async () => {
        settingsService.getRaw.mockResolvedValue({
            enabled: true,
            zapBaseUrl: 'http://zap:8080',
            apiKey: 'key',
            connectTimeoutSeconds: 10,
            maxScanDurationMinutes: 5,
            maxConcurrentScans: 1,
            allowBaselineScan: true,
            allowedTargetPatterns: ['*.internal'],
            blockedTargetPatterns: [],
            defaultRiskThresholdForNotification: 'HIGH',
        });
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);

        await service.scanUrl({ targetUrl: 'https://demo.internal', targetProfileId: 'legacy-default' }, 'op-legacy');

        expect(policyService.getTargetProfile).toHaveBeenCalledWith(expect.objectContaining({
            targetProfiles: [expect.objectContaining({
                id: 'legacy-default',
                allowedTargetPatterns: ['*.internal'],
                maxScanDurationMinutes: 5,
            })],
        }), 'legacy-default');
    });

    it('rejects an active scan before contacting the ZAP service', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        await expect(service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'active' }, 'op-1'))
            .rejects.toThrow('Passive Spider Scan');
        expect(zapClient.getVersion).not.toHaveBeenCalled();
    });

    it('rejects baseline scan when disabled', async () => {
        settingsService.getRaw.mockResolvedValue({
            enabled: true,
            zapBaseUrl: 'http://zap:8080',
            apiKey: '',
            connectTimeoutSeconds: 10,
            maxScanDurationMinutes: 1,
            maxConcurrentScans: 1,
            allowBaselineScan: false,
            allowActiveScan: false,
            allowedTargetPatterns: ['*.internal'],
            blockedTargetPatterns: [],
            defaultRiskThresholdForNotification: 'HIGH',
        });
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        await expect(service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }, 'op-1'))
            .rejects.toThrow(BadRequestException);
    });

    it('stops an active spider when cancellation is requested', async () => {
        let resolveStatus: (value: number) => void = () => undefined;
        zapClient.spiderStatus.mockReturnValue(new Promise<number>((resolve) => {
            resolveStatus = resolve;
        }));

        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        const scanPromise = service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }, 'op-1');

        await waitUntil(() => zapClient.spiderStatus.mock.calls.length > 0);
        await expect(service.cancelScan('op-1')).resolves.toBe(true);
        resolveStatus(100);

        await expect(scanPromise).rejects.toThrow(BadRequestException);
        expect(zapClient.stopSpider).toHaveBeenCalledWith(expect.any(Object), '1');
    });

    it('uses temporary Authorization header rules without storing the secret in scan evidence', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        const result = await service.scanUrl({
            targetUrl: 'https://demo.internal',
            scanMode: 'baseline',
            authentication: {
                type: 'authorization',
                value: 'Bearer secret-token',
            },
        }, 'op-auth');

        expect(zapClient.addRequestHeaderRule).toHaveBeenCalledWith(
            expect.objectContaining({ baseUrl: 'http://zap:8080', apiKey: 'key' }),
            'jasca-auth-op-auth-authorization',
            'Authorization',
            'Bearer secret-token',
        );
        expect(zapClient.removeRule).toHaveBeenCalledWith(
            expect.objectContaining({ baseUrl: 'http://zap:8080', apiKey: 'key' }),
            'jasca-auth-op-auth-authorization',
        );
        expect(JSON.stringify(result)).not.toContain('secret-token');
        expect(result.Metadata.JascaScanEvidence.authentication).toEqual({
            type: 'authorization',
            requestHeaders: ['Authorization'],
        });
    });

    it('uses temporary Cookie header rules for cookie-authenticated scans', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        await service.scanUrl({
            targetUrl: 'https://demo.internal',
            scanMode: 'baseline',
            authentication: {
                type: 'cookie',
                value: 'SESSION=abc; Path=/',
            },
        }, 'op-cookie');

        expect(zapClient.addRequestHeaderRule).toHaveBeenCalledWith(
            expect.any(Object),
            'jasca-auth-op-cookie-cookie',
            'Cookie',
            'SESSION=abc; Path=/',
        );
        expect(zapClient.removeRule).toHaveBeenCalledWith(
            expect.any(Object),
            'jasca-auth-op-cookie-cookie',
        );
    });

    it('rejects concurrent ZAP scans when the administrator limit is already reached', async () => {
        let resolveStatus: (value: number) => void = () => undefined;
        zapClient.spiderStatus.mockReturnValue(new Promise<number>((resolve) => {
            resolveStatus = resolve;
        }));

        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        const firstScan = service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }, 'op-1');

        await waitUntil(() => zapClient.spiderStatus.mock.calls.length > 0);
        await expect(service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }, 'op-2'))
            .rejects.toThrow(BadRequestException);

        resolveStatus(100);
        await firstScan;
    });

    it('enforces the concurrency limit even when no operation id is provided', async () => {
        let resolveStatus: (value: number) => void = () => undefined;
        zapClient.spiderStatus.mockReturnValue(new Promise<number>((resolve) => {
            resolveStatus = resolve;
        }));

        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        const firstScan = service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' });

        await waitUntil(() => zapClient.spiderStatus.mock.calls.length > 0);
        await expect(service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }))
            .rejects.toThrow(BadRequestException);

        resolveStatus(100);
        await firstScan;
    });
});

async function waitUntil(predicate: () => boolean): Promise<void> {
    for (let i = 0; i < 20; i += 1) {
        if (predicate()) {
            return;
        }
        await new Promise((resolve) => setTimeout(resolve, 1));
    }
    throw new Error('Timed out waiting for test condition');
}
