import { BadRequestException } from '@nestjs/common';
import { ZapPolicyService } from './zap-policy.service';

describe('ZapPolicyService', () => {
    const settings = {
        enabled: true,
        zapBaseUrl: 'http://zap:8080',
        connectTimeoutSeconds: 10,
        maxScanDurationMinutes: 30,
        maxConcurrentScans: 1,
        allowBaselineScan: true,
        allowActiveScan: false,
        allowedTargetPatterns: ['*.internal'],
        blockedTargetPatterns: [],
        defaultRiskThresholdForNotification: 'HIGH',
        targetProfiles: [
            {
                id: 'internal-app',
                name: 'Internal App',
                enabled: true,
                allowedTargetPatterns: ['app.internal'],
                blockedTargetPatterns: ['admin.app.internal'],
                maxScanDurationMinutes: 10,
                defaultRiskThresholdForNotification: 'MEDIUM',
            },
            {
                id: 'disabled-profile',
                name: 'Disabled',
                enabled: false,
                allowedTargetPatterns: ['disabled.internal'],
                blockedTargetPatterns: [],
                maxScanDurationMinutes: 10,
                defaultRiskThresholdForNotification: 'HIGH',
            },
        ],
    };

    it('rejects a URL that is outside the selected target profile', () => {
        const service = new ZapPolicyService();

        expect(() => (service as any).validateTargetUrl('https://outside.internal', settings, 'internal-app'))
            .toThrow('selected profile');
    });

    it('rejects a disabled target profile', () => {
        const service = new ZapPolicyService();

        expect(() => (service as any).validateTargetUrl('https://disabled.internal', settings, 'disabled-profile'))
            .toThrow(BadRequestException);
    });

    it('rejects a profile with an invalid execution limit', () => {
        const service = new ZapPolicyService();
        const invalidSettings = {
            ...settings,
            targetProfiles: [{ ...settings.targetProfiles[0], maxScanDurationMinutes: 0 }],
        };

        expect(() => (service as any).validateTargetUrl('https://app.internal', invalidSettings, 'internal-app'))
            .toThrow('profile is invalid');
    });
});
