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
