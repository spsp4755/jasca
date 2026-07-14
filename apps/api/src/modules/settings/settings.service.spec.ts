import { SettingsService } from './settings.service';

describe('SettingsService Clustara secret handling', () => {
    const stored = {
        enabled: true,
        authType: 'X_API_KEY',
        credential: 'internal-secret',
    };

    it('masks Clustara credentials in keyed reads', async () => {
        const prisma = {
            systemSettings: {
                findUnique: jest.fn().mockResolvedValue({ value: stored }),
            },
        } as any;
        const service = new SettingsService(prisma);

        await expect(service.get('clustara')).resolves.toEqual({
            enabled: true,
            authType: 'X_API_KEY',
            credentialConfigured: true,
        });
    });

    it('masks Clustara credentials in aggregate reads', async () => {
        const prisma = {
            systemSettings: {
                findMany: jest.fn().mockResolvedValue([{ key: 'clustara', value: stored }]),
            },
        } as any;
        const service = new SettingsService(prisma);

        const settings = await service.getAll();
        expect(settings.clustara).toEqual({
            enabled: true,
            authType: 'X_API_KEY',
            credentialConfigured: true,
        });
    });
});

describe('SettingsService Harbor secret handling', () => {
    const stored = {
        enabled: true,
        baseUrl: 'https://harbor.example.test/',
        username: 'robot$jasca',
        password: 'registry-password',
        webhookSecret: 'webhook-secret',
        allowedProjects: ['platform'],
        defaultProjectId: 'jasca-project',
        autoScanOnPush: true,
    };

    it('masks Harbor secrets in generic keyed reads', async () => {
        const prisma = {
            systemSettings: {
                findUnique: jest.fn().mockResolvedValue({ value: stored }),
            },
        } as any;
        const service = new SettingsService(prisma);

        await expect(service.get('harbor')).resolves.toEqual({
            enabled: true,
            baseUrl: 'https://harbor.example.test',
            username: 'robot$jasca',
            allowedProjects: ['platform'],
            defaultProjectId: 'jasca-project',
            autoScanOnPush: true,
            passwordConfigured: true,
            webhookSecretConfigured: true,
        });
    });

    it('masks Harbor secrets in generic aggregate reads', async () => {
        const prisma = {
            systemSettings: {
                findMany: jest.fn().mockResolvedValue([{ key: 'harbor', value: stored }]),
            },
        } as any;
        const service = new SettingsService(prisma);

        await expect(service.getAll()).resolves.toMatchObject({
            harbor: {
                enabled: true,
                baseUrl: 'https://harbor.example.test',
                username: 'robot$jasca',
                passwordConfigured: true,
                webhookSecretConfigured: true,
            },
        });
    });

    it('normalizes generic Harbor updates and preserves masked secrets', async () => {
        const prisma = {
            systemSettings: {
                findUnique: jest.fn().mockResolvedValue({ value: stored }),
                upsert: jest.fn().mockImplementation(({ create }) => Promise.resolve({
                    key: 'harbor',
                    value: create.value,
                })),
            },
        } as any;
        const service = new SettingsService(prisma);

        await expect(service.set('harbor', {
            ...stored,
            baseUrl: ' https://harbor.example.test/// ',
            password: '********',
            webhookSecret: '********',
            allowedProjects: [' platform ', '', 123],
        })).resolves.toMatchObject({
            value: {
                baseUrl: 'https://harbor.example.test',
                allowedProjects: ['platform', '123'],
                passwordConfigured: true,
                webhookSecretConfigured: true,
            },
        });

        expect(prisma.systemSettings.upsert).toHaveBeenCalledWith(expect.objectContaining({
            create: expect.objectContaining({
                value: expect.objectContaining({
                    password: 'registry-password',
                    webhookSecret: 'webhook-secret',
                }),
            }),
        }));
    });
});

describe('SettingsService ZAP profile compatibility', () => {
    it('exposes a default profile for existing allowlist-only ZAP settings', async () => {
        const prisma = {
            systemSettings: {
                findUnique: jest.fn().mockResolvedValue({ value: {
                    enabled: true,
                    allowedTargetPatterns: ['*.internal'],
                    blockedTargetPatterns: [],
                    maxScanDurationMinutes: 20,
                    defaultRiskThresholdForNotification: 'HIGH',
                } }),
            },
        } as any;
        const service = new SettingsService(prisma);

        await expect(service.get('zap')).resolves.toEqual(expect.objectContaining({
            targetProfiles: [expect.objectContaining({
                id: 'legacy-default',
                allowedTargetPatterns: ['*.internal'],
                maxScanDurationMinutes: 20,
            })],
        }));
    });
});
