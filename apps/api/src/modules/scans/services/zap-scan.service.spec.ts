import { BadRequestException } from '@nestjs/common';
import { ZapScanService } from './zap-scan.service';

describe('ZapScanService', () => {
    const settingsService = {
        get: jest.fn(),
        getRaw: jest.fn(),
    };
    const policyService = {
        validateTargetUrl: jest.fn(),
    };
    const zapClient = {
        getVersion: jest.fn(),
        spiderScan: jest.fn(),
        spiderStatus: jest.fn(),
        alerts: jest.fn(),
        stopSpider: jest.fn(),
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
        });
        policyService.validateTargetUrl.mockReturnValue(new URL('https://demo.internal'));
        zapClient.getVersion.mockResolvedValue('2.15.0');
        zapClient.spiderScan.mockResolvedValue('1');
        zapClient.spiderStatus.mockResolvedValue(100);
        zapClient.stopSpider.mockResolvedValue(undefined);
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
        const result = await service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }, 'op-1');

        expect(policyService.validateTargetUrl).toHaveBeenCalledWith('https://demo.internal', expect.objectContaining({
            enabled: true,
            apiKey: 'key',
        }));
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
        }));
    });

    it('rejects active scan when disabled', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        await expect(service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'active' }, 'op-1'))
            .rejects.toThrow(BadRequestException);
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
