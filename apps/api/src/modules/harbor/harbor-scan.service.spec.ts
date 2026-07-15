import {
    BadRequestException,
    ForbiddenException,
    UnauthorizedException,
} from '@nestjs/common';
import { HarborScanService } from './harbor-scan.service';

describe('HarborScanService', () => {
    const imageDigest = `sha256:${'a'.repeat(64)}`;
    const requestUser = {
        id: 'user-1',
        organizationId: 'org-1',
        roles: [{ role: 'DEVELOPER', scope: 'ORGANIZATION', scopeId: 'org-1' }],
    };
    const manualScanInput = {
        projectId: 'jasca-project',
        imageRef: 'harbor.example.test/platform/backend:latest',
        imageDigest,
        tag: 'latest',
    };
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
        project?: { id: string; organizationId: string } | null;
        job?: Record<string, any> | null;
        scanImageReference?: jest.Mock;
        uploadScan?: jest.Mock;
    } = {}) {
        const jobStore: { current: Record<string, any> | null } = {
            current: overrides.job === undefined ? null : overrides.job,
        };
        const settingsService = {
            getRaw: jest.fn().mockResolvedValue({ ...settings, ...overrides.harborSettings }),
        };
        const trivyScanService = {
            scanImageReference: overrides.scanImageReference || jest.fn().mockResolvedValue({
                rawResult: {
                    SchemaVersion: 2,
                    ArtifactName: 'harbor.example.test/platform/backend',
                    Metadata: { JascaScanEvidence: { executedBy: 'jasca' } },
                    Results: [],
                },
            }),
        };
        const scansService = {
            uploadScan: overrides.uploadScan || jest.fn().mockResolvedValue({ id: 'scan-1' }),
        };

        const matchesWhere = (where: Record<string, any>): boolean => {
            if (!jobStore.current) return false;
            return Object.entries(where).every(([field, expected]) => {
                if (field === 'OR') {
                    return expected.some((condition: Record<string, any>) => matchesWhere(condition));
                }
                if (expected && typeof expected === 'object' && 'lte' in expected) {
                    const actual = jobStore.current?.[field];
                    return actual instanceof Date && actual.getTime() <= expected.lte.getTime();
                }
                return jobStore.current?.[field] === expected;
            });
        };
        const harborScanJob = {
            create: jest.fn(async ({ data }: { data: Record<string, any> }) => {
                if (jobStore.current) {
                    throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
                }
                jobStore.current = { id: 'job-1', ...data };
                return { id: 'job-1' };
            }),
            updateMany: jest.fn(async ({ where, data }: {
                where: Record<string, any>;
                data: Record<string, any>;
            }) => {
                if (!matchesWhere(where)) return { count: 0 };
                Object.assign(jobStore.current!, data);
                return { count: 1 };
            }),
        };

        const prisma = {
            project: {
                findUnique: jest.fn().mockResolvedValue(
                    overrides.project === undefined
                        ? { id: 'jasca-project', organizationId: 'org-1' }
                        : overrides.project,
                ),
            },
            harborScanJob,
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
            harborScanJob,
            jobStore,
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

    it('creates a RUNNING job before Trivy starts and completes it only after upload returns', async () => {
        let uploadFinished = false;
        const uploadScan = jest.fn().mockImplementation(async () => {
            uploadFinished = true;
            return { id: 'scan-1' };
        });
        const scanImageReference = jest.fn().mockImplementation(async () => ({
            rawResult: { Metadata: {}, Results: [] },
        }));
        const { service, harborScanJob, jobStore, prisma } = createService({
            scanImageReference,
            uploadScan,
        });

        scanImageReference.mockImplementation(async () => {
            expect(jobStore.current).toEqual(expect.objectContaining({ status: 'RUNNING' }));
            expect(uploadFinished).toBe(false);
            return { rawResult: { Metadata: {}, Results: [] } };
        });

        await expect(service.scan(manualScanInput, requestUser)).resolves.toEqual({
            duplicate: false,
            scan: { id: 'scan-1' },
        });
        expect(harborScanJob.create).toHaveBeenCalledTimes(1);
        expect(jobStore.current).toEqual(expect.objectContaining({
            status: 'COMPLETED',
            scanResultId: 'scan-1',
            completedAt: expect.any(Date),
        }));
        expect('$transaction' in prisma).toBe(false);
    });

    it('returns duplicate on a unique RUNNING collision without executing Trivy', async () => {
        const { service, trivyScanService } = createService({
            job: {
                id: 'existing-job',
                projectId: manualScanInput.projectId,
                imageDigest,
                status: 'RUNNING',
                startedAt: new Date(),
                completedAt: null,
            },
        });

        await expect(service.scan(manualScanInput, requestUser)).resolves.toEqual({ duplicate: true });
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
    });

    it('marks a failed scan with a redacted error and permits a retry', async () => {
        const scanImageReference = jest.fn()
            .mockRejectedValueOnce(new Error('Trivy rejected registry-password for robot$jasca'))
            .mockResolvedValueOnce({ rawResult: { Metadata: {}, Results: [] } });
        const { service, trivyScanService, jobStore } = createService({ scanImageReference });

        await expect(service.scan(manualScanInput, requestUser)).rejects.toThrow('registry-password');
        expect(jobStore.current).toEqual(expect.objectContaining({
            status: 'FAILED',
            completedAt: expect.any(Date),
        }));
        expect(jobStore.current?.error).not.toContain('registry-password');
        expect(jobStore.current?.error).not.toContain('robot$jasca');

        await expect(service.scan(manualScanInput, requestUser)).resolves.toEqual({
            duplicate: false,
            scan: { id: 'scan-1' },
        });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledTimes(2);
        expect(jobStore.current).toEqual(expect.objectContaining({
            status: 'COMPLETED',
            error: null,
        }));
    });

    it('marks the job FAILED when scan persistence rejects the upload', async () => {
        const uploadScan = jest.fn().mockRejectedValue(new Error('Persistence failed for registry-password'));
        const { service, jobStore } = createService({ uploadScan });

        await expect(service.scan(manualScanInput, requestUser)).rejects.toThrow('Persistence failed');
        expect(jobStore.current).toEqual(expect.objectContaining({
            status: 'FAILED',
            completedAt: expect.any(Date),
        }));
        expect(jobStore.current?.error).toBe('Persistence failed for [REDACTED]');
    });

    it('fails and reclaims a stale RUNNING job before executing Trivy', async () => {
        const { service, harborScanJob, trivyScanService, jobStore } = createService({
            job: {
                id: 'stale-job',
                projectId: manualScanInput.projectId,
                imageDigest,
                status: 'RUNNING',
                startedAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
                completedAt: null,
            },
        });

        await expect(service.scan(manualScanInput, requestUser)).resolves.toEqual({
            duplicate: false,
            scan: { id: 'scan-1' },
        });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledTimes(1);
        expect(harborScanJob.updateMany).toHaveBeenCalledWith(expect.objectContaining({
            where: expect.objectContaining({
                status: 'RUNNING',
                startedAt: { lte: expect.any(Date) },
            }),
            data: expect.objectContaining({ status: 'FAILED' }),
        }));
        expect(jobStore.current).toEqual(expect.objectContaining({ status: 'COMPLETED' }));
    });

    it('deduplicates a recently completed job within the configured result TTL', async () => {
        const { service, trivyScanService } = createService({
            job: {
                id: 'completed-job',
                projectId: manualScanInput.projectId,
                imageDigest,
                status: 'COMPLETED',
                startedAt: new Date(Date.now() - 60_000),
                completedAt: new Date(),
            },
        });

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .resolves.toEqual({ accepted: true, duplicate: true });
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
    });

    it('reclaims a completed job after the configured result TTL expires', async () => {
        const { service, trivyScanService, jobStore } = createService({
            job: {
                id: 'completed-job',
                projectId: manualScanInput.projectId,
                imageDigest,
                status: 'COMPLETED',
                startedAt: new Date(Date.now() - 12 * 60 * 1000),
                completedAt: new Date(Date.now() - 11 * 60 * 1000),
            },
        });

        await expect(service.scan(manualScanInput, requestUser)).resolves.toEqual({
            duplicate: false,
            scan: { id: 'scan-1' },
        });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledTimes(1);
        expect(jobStore.current).toEqual(expect.objectContaining({ status: 'COMPLETED' }));
    });

    it('uses the authenticated user for manual project access and requester attribution', async () => {
        const { service, scansService } = createService();

        await service.scan({
            ...manualScanInput,
            requestedById: 'impersonated-user',
        } as any, requestUser);

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
            requestUser,
        );
    });

    it('rejects a manual scan when the authenticated user cannot access the project', async () => {
        const { service, trivyScanService } = createService({
            project: { id: 'jasca-project', organizationId: 'org-2' },
        });

        await expect(service.scan(manualScanInput, requestUser))
            .rejects.toBeInstanceOf(ForbiddenException);
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
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
