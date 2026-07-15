import {
    BadRequestException,
    ForbiddenException,
    UnauthorizedException,
} from '@nestjs/common';
import { HarborScanService } from './harbor-scan.service';

describe('HarborScanService', () => {
    const imageDigest = `sha256:${'a'.repeat(64)}`;
    const settings = {
        enabled: true,
        baseUrl: 'https://harbor.example.test',
        username: 'robot$jasca',
        password: 'registry-password',
        webhookSecret: 'webhook-secret',
        allowedProjects: ['platform'],
        defaultProjectId: 'jasca-project',
        autoScanOnPush: true,
    };
    const pushPayload = {
        type: 'PUSH_ARTIFACT',
        occur_at: 1680501893,
        operator: 'admin',
        event_data: {
            resources: [{
                digest: imageDigest,
                tag: 'latest',
                resource_url: 'harbor.example.test/platform/backend:latest',
            }],
            repository: {
                date_created: 1680501893,
                name: 'backend',
                namespace: 'platform',
                repo_full_name: 'platform/backend',
                repo_type: 'private',
            },
        },
    };

    function createService(overrides: {
        harborSettings?: Partial<typeof settings>;
        recentScan?: { id: string } | null;
        scanResult?: Promise<any>;
    } = {}) {
        const settingsService = {
            getRaw: jest.fn().mockResolvedValue({ ...settings, ...overrides.harborSettings }),
        };
        const trivyScanService = {
            scanImageReference: jest.fn().mockReturnValue(overrides.scanResult || Promise.resolve({
                rawResult: {
                    SchemaVersion: 2,
                    ArtifactName: 'harbor.example.test/platform/backend',
                    Metadata: { JascaScanEvidence: { executedBy: 'jasca' } },
                    Results: [],
                },
            })),
        };
        const scansService = {
            uploadScan: jest.fn().mockResolvedValue({ id: 'scan-1' }),
        };
        const prisma = {
            project: {
                findUnique: jest.fn().mockResolvedValue({ id: 'jasca-project' }),
            },
            scanResult: {
                findFirst: jest.fn().mockResolvedValue(overrides.recentScan || null),
            },
        };

        return {
            service: new HarborScanService(
                settingsService as any,
                trivyScanService as any,
                scansService as any,
                prisma as any,
            ),
            settingsService,
            trivyScanService,
            scansService,
            prisma,
        };
    }

    it('rejects a bad Authorization Bearer secret', async () => {
        const { service, trivyScanService } = createService();

        await expect(service.handleWebhook('Bearer wrong-secret', pushPayload))
            .rejects.toBeInstanceOf(UnauthorizedException);
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
    });

    it('accepts the official default PUSH_ARTIFACT payload and scans its immutable digest', async () => {
        const { service, trivyScanService, scansService } = createService();

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .resolves.toEqual({ accepted: true });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledWith(
            `harbor.example.test/platform/backend@${imageDigest}`,
            expect.objectContaining({
                registryUsername: 'robot$jasca',
                registryPassword: 'registry-password',
            }),
        );
        expect(scansService.uploadScan).toHaveBeenCalledWith(
            'jasca-project',
            expect.objectContaining({
                sourceType: 'TRIVY_JSON',
                imageRef: 'harbor.example.test/platform/backend:latest',
                imageDigest,
                tag: 'latest',
            }),
            expect.objectContaining({
                Metadata: expect.objectContaining({
                    JascaScanEvidence: expect.objectContaining({
                        harbor: expect.objectContaining({ trigger: 'webhook' }),
                    }),
                }),
            }),
            expect.objectContaining({ userAgent: 'Harbor webhook scan' }),
        );
    });

    it('rejects webhook pushes from a Harbor project that is not approved', async () => {
        const { service, trivyScanService } = createService();
        const blockedPayload = {
            ...pushPayload,
            event_data: {
                ...pushPayload.event_data,
                repository: {
                    ...pushPayload.event_data.repository,
                    namespace: 'unapproved',
                    repo_full_name: 'unapproved/backend',
                },
                resources: [{
                    ...pushPayload.event_data.resources[0],
                    resource_url: 'harbor.example.test/unapproved/backend:latest',
                }],
            },
        };

        await expect(service.handleWebhook('Bearer webhook-secret', blockedPayload))
            .rejects.toBeInstanceOf(ForbiddenException);
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
    });

    it('returns an accepted duplicate response for a recently completed image digest', async () => {
        const { service, trivyScanService } = createService({ recentScan: { id: 'existing-scan' } });

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .resolves.toEqual({ accepted: true, duplicate: true });
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
    });

    it('deduplicates the same image reference and digest while its first scan is active', async () => {
        let finishScan: ((result: any) => void) | undefined;
        const scanResult = new Promise((resolve) => {
            finishScan = resolve;
        });
        const { service, trivyScanService } = createService({ scanResult });
        const input = {
            projectId: 'jasca-project',
            imageRef: 'harbor.example.test/platform/backend:latest',
            imageDigest,
            tag: 'latest',
            trigger: 'manual' as const,
        };

        const firstScan = service.scan(input);
        await Promise.resolve();
        await Promise.resolve();
        await expect(service.scan(input)).resolves.toEqual({ duplicate: true });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledTimes(1);

        finishScan?.({ rawResult: { Metadata: {}, Results: [] } });
        await firstScan;
    });

    it('preserves manual trigger evidence and requester attribution', async () => {
        const { service, scansService } = createService();

        await service.scan({
            projectId: 'jasca-project',
            imageRef: 'harbor.example.test/platform/backend:latest',
            imageDigest,
            tag: 'latest',
            trigger: 'manual',
            requestedById: 'user-1',
        });

        expect(scansService.uploadScan).toHaveBeenCalledWith(
            'jasca-project',
            expect.any(Object),
            expect.objectContaining({
                Metadata: expect.objectContaining({
                    JascaScanEvidence: expect.objectContaining({
                        harbor: expect.objectContaining({ trigger: 'manual' }),
                    }),
                }),
            }),
            expect.objectContaining({
                uploadedById: 'user-1',
                userAgent: 'Harbor manual scan',
            }),
        );
    });

    it('rejects webhooks when the Harbor integration or automatic push scanning is disabled', async () => {
        const { service } = createService({ harborSettings: { autoScanOnPush: false } });

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .rejects.toBeInstanceOf(ForbiddenException);
    });

    it('rejects unsupported webhook event types', async () => {
        const { service } = createService();

        await expect(service.handleWebhook('Bearer webhook-secret', {
            ...pushPayload,
            type: 'SCANNING_COMPLETED',
        })).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('rejects push payloads without an image digest', async () => {
        const { service } = createService();

        await expect(service.handleWebhook('Bearer webhook-secret', {
            ...pushPayload,
            event_data: {
                ...pushPayload.event_data,
                resources: [{ ...pushPayload.event_data.resources[0], digest: '' }],
            },
        })).rejects.toBeInstanceOf(BadRequestException);
    });

    it('rejects webhooks without a default JASCA project', async () => {
        const { service } = createService({ harborSettings: { defaultProjectId: '' } });

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .rejects.toBeInstanceOf(BadRequestException);
    });
});
