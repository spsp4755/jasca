import { BadRequestException } from '@nestjs/common';
import { HarborService } from './harbor.service';

describe('HarborService', () => {
    const settings = {
        enabled: true,
        baseUrl: 'https://harbor.example.test/',
        username: 'robot$jasca',
        password: 'registry-password',
        webhookSecret: 'webhook-secret',
        allowedProjects: ['platform'],
        defaultProjectId: 'jasca-project',
        autoScanOnPush: true,
    };

    function createService(fetchImpl = jest.fn()) {
        const service = new HarborService({
            getRaw: jest.fn().mockResolvedValue(settings),
            set: jest.fn().mockResolvedValue(undefined),
        } as any);
        jest.spyOn(globalThis, 'fetch').mockImplementation(fetchImpl);
        return service;
    }

    it('masks registry credentials and webhook secrets in settings responses', async () => {
        const service = createService();

        await expect(service.getSettings()).resolves.toEqual({
            enabled: true,
            baseUrl: 'https://harbor.example.test',
            username: 'robot$jasca',
            passwordConfigured: true,
            webhookSecretConfigured: true,
            allowedProjects: ['platform'],
            defaultProjectId: 'jasca-project',
            autoScanOnPush: true,
        });
    });

    it('uses Basic authentication for Harbor v2 project requests', async () => {
        const fetchImpl = jest.fn().mockResolvedValue({
            ok: true,
            json: jest.fn().mockResolvedValue([]),
        });
        const service = createService(fetchImpl);

        await expect(service.listProjects()).resolves.toEqual([]);
        expect(fetchImpl).toHaveBeenCalledWith(
            'https://harbor.example.test/api/v2.0/projects',
            expect.objectContaining({
                headers: expect.objectContaining({
                    Authorization: `Basic ${Buffer.from('robot$jasca:registry-password').toString('base64')}`,
                }),
            }),
        );
    });

    it('encodes nested repository names in artifact URLs', async () => {
        const fetchImpl = jest.fn().mockResolvedValue({
            ok: true,
            json: jest.fn().mockResolvedValue([]),
        });
        const service = createService(fetchImpl);

        await service.listArtifacts('platform', 'backend/api');

        expect(fetchImpl).toHaveBeenCalledWith(
            'https://harbor.example.test/api/v2.0/projects/platform/repositories/backend%2Fapi/artifacts',
            expect.any(Object),
        );
    });

    it('rejects repository access outside the allowed projects', async () => {
        const service = createService();

        await expect(service.listRepositories('unapproved')).rejects.toBeInstanceOf(BadRequestException);
    });

    it('rejects non-HTTPS registry URLs outside local test hosts', async () => {
        const service = createService();

        await expect(service.updateSettings({ baseUrl: 'http://harbor.example.test' }))
            .rejects.toBeInstanceOf(BadRequestException);
    });
});
