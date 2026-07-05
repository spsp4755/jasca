import { BadRequestException } from '@nestjs/common';
import { ZapPolicyService, ZapSettings } from './zap-policy.service';

describe('ZapPolicyService', () => {
    const service = new ZapPolicyService();
    const settings: ZapSettings = {
        enabled: true,
        zapBaseUrl: 'http://zap-scanner:8080',
        apiKey: 'secret',
        connectTimeoutSeconds: 10,
        maxScanDurationMinutes: 30,
        maxConcurrentScans: 1,
        allowBaselineScan: true,
        allowActiveScan: false,
        allowedTargetPatterns: ['*.internal', 'https://app.koreacb.com'],
        blockedTargetPatterns: ['admin.internal'],
        defaultRiskThresholdForNotification: 'HIGH',
    };

    it('allows a matching internal target', () => {
        expect(service.validateTargetUrl('https://demo.internal/login', settings).href)
            .toBe('https://demo.internal/login');
    });

    it('allows an exact URL policy with a deeper path', () => {
        expect(service.validateTargetUrl('https://app.koreacb.com/dashboard', settings).href)
            .toBe('https://app.koreacb.com/dashboard');
    });

    it('blocks targets when ZAP is disabled', () => {
        expect(() => service.validateTargetUrl('https://demo.internal', { ...settings, enabled: false }))
            .toThrow(BadRequestException);
    });

    it('blocks targets when allowlist is empty', () => {
        expect(() => service.validateTargetUrl('https://demo.internal', { ...settings, allowedTargetPatterns: [] }))
            .toThrow(BadRequestException);
    });

    it('blocks targets outside the allowlist', () => {
        expect(() => service.validateTargetUrl('https://example.com', settings))
            .toThrow(BadRequestException);
    });

    it('blocks explicit denylist matches', () => {
        expect(() => service.validateTargetUrl('https://admin.internal', settings))
            .toThrow(BadRequestException);
    });

    it('rejects non-http URLs', () => {
        expect(() => service.validateTargetUrl('file:///etc/passwd', settings))
            .toThrow(BadRequestException);
    });
});
