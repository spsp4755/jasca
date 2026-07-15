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
        recentScan?: { id: string } | null;
        findRecentScan?: jest.Mock;
        project?: { id: string; organizationId: string } | null;
        scanResult?: Promise<any>;
        tryAdvisoryLock?: () => boolean | Promise<boolean>;
        releaseAdvisoryLock?: () => void | Promise<void>;
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
        const findRecentScan = overrides.findRecentScan || jest.fn().mockResolvedValue(overrides.recentScan ?? null);
        const queryRaw = jest.fn(async (query: TemplateStringsArray) => {
            const sql = query.join('');
            if (sql.includes('pg_try_advisory_lock')) {
                const acquired = overrides.tryAdvisoryLock
                    ? await overrides.tryAdvisoryLock()
                    : true;
                return [{ acquired }];
            }
            if (sql.includes('pg_advisory_unlock')) {
                await overrides.releaseAdvisoryLock?.();
                return [{ released: true }];
            }
            throw new Error(`Unexpected raw query: ${sql}`);
        });
        const transactionClient = {
            scanResult: { findFirst: findRecentScan },
            $queryRaw: queryRaw,
        };
        const prisma = {
            project: {
                findUnique: jest.fn().mockResolvedValue(
                    overrides.project === undefined
                        ? { id: 'jasca-project', organizationId: 'org-1' }
                        : overrides.project,
                ),
            },
            scanResult: {
                findFirst: findRecentScan,
            },
            $transaction: jest.fn((callback: (tx: typeof transactionClient) => Promise<any>) => callback(transactionClient)),
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
            queryRaw,
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
        const { service, trivyScanService, prisma } = createService({ recentScan: { id: 'existing-scan' } });

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .resolves.toEqual({ accepted: true, duplicate: true });
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
        expect(prisma.scanResult.findFirst).toHaveBeenCalledWith(expect.objectContaining({
            where: expect.objectContaining({
                summary: { isNot: null },
            }),
        }));
    });

    it('retries a digest when a prior scan row never reached completed persistence', async () => {
        const findRecentScan = jest.fn().mockImplementation(({ where }) => Promise.resolve(
            where.summary?.isNot === null ? null : { id: 'incomplete-scan' },
        ));
        const { service, trivyScanService } = createService({ findRecentScan });

        await expect(service.handleWebhook('Bearer webhook-secret', pushPayload))
            .resolves.toEqual({ accepted: true });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledTimes(1);
    });

    it('deduplicates the same image reference and digest while its first scan is active', async () => {
        let finishScan: ((result: any) => void) | undefined;
        const scanResult = new Promise((resolve) => {
            finishScan = resolve;
        });
        const { service, trivyScanService } = createService({ scanResult });

        const firstScan = (service as any).scan(manualScanInput, requestUser);
        await Promise.resolve();
        await Promise.resolve();
        await expect((service as any).scan(manualScanInput, requestUser)).resolves.toEqual({ duplicate: true });
        expect(trivyScanService.scanImageReference).toHaveBeenCalledTimes(1);

        finishScan?.({ rawResult: { Metadata: {}, Results: [] } });
        await firstScan;
    });

    it('uses the authenticated user for manual project access and requester attribution', async () => {
        const { service, scansService } = createService();

        await (service as any).scan({
            ...manualScanInput,
            requestedById: 'impersonated-user',
        }, requestUser);

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

        await expect((service as any).scan(manualScanInput, requestUser))
            .rejects.toBeInstanceOf(ForbiddenException);
        expect(trivyScanService.scanImageReference).not.toHaveBeenCalled();
    });

    it('uses a Postgres advisory lock to deduplicate active scans across service instances', async () => {
        let finishScan: ((result: any) => void) | undefined;
        const scanResult = new Promise((resolve) => {
            finishScan = resolve;
        });
        let lockHeld = false;
        const tryAdvisoryLock = jest.fn(() => {
            if (lockHeld) return false;
            lockHeld = true;
            return true;
        });
        const releaseAdvisoryLock = jest.fn(() => {
            lockHeld = false;
        });
        const first = createService({ scanResult, tryAdvisoryLock, releaseAdvisoryLock });
        const secondService = new HarborScanService(
            first.settingsService as any,
            first.trivyScanService as any,
            first.scansService as any,
            first.prisma as any,
        );

        const firstScan = (first.service as any).scan(manualScanInput, requestUser);
        await Promise.resolve();
        await Promise.resolve();
        const secondScan = (secondService as any).scan(manualScanInput, requestUser);
        try {
            const secondOutcome = await Promise.race([
                secondScan,
                new Promise((resolve) => setTimeout(() => resolve('still-running'), 50)),
            ]);
            expect(secondOutcome).toEqual({ duplicate: true });
            expect(first.trivyScanService.scanImageReference).toHaveBeenCalledTimes(1);
        } finally {
            finishScan?.({ rawResult: { Metadata: {}, Results: [] } });
        }

        await firstScan;
        expect(tryAdvisoryLock).toHaveBeenCalledTimes(2);
        const lockQueries = first.queryRaw.mock.calls.filter(([query]) =>
            query.join('').includes('pg_try_advisory_lock'),
        );
        expect(lockQueries[0].slice(1)).toEqual(lockQueries[1].slice(1));
    });

    it('releases the advisory lock when Trivy execution fails', async () => {
        let lockHeld = false;
        const releaseAdvisoryLock = jest.fn(() => {
            lockHeld = false;
        });
        const { service, queryRaw } = createService({
            scanResult: Promise.reject(new Error('Trivy failed')),
            tryAdvisoryLock: () => {
                lockHeld = true;
                return true;
            },
            releaseAdvisoryLock,
        });

        await expect((service as any).scan(manualScanInput, requestUser)).rejects.toThrow('Trivy failed');
        expect(releaseAdvisoryLock).toHaveBeenCalledTimes(1);
        expect(lockHeld).toBe(false);
        expect(queryRaw.mock.calls.some(([query]) => query.join('').includes('pg_advisory_unlock'))).toBe(true);
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
