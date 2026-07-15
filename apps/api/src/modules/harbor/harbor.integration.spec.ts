import {
    ExecutionContext,
    INestApplication,
    UnauthorizedException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { PrismaService } from '../../prisma/prisma.service';
import { ScansService } from '../scans/scans.service';
import { TrivyScanService } from '../scans/services/trivy-scan.service';
import { SettingsService } from '../settings/settings.service';
import { HarborScanService } from './harbor-scan.service';
import { HarborController, HarborWebhookController } from './harbor.controller';
import { HarborService } from './harbor.service';

describe('Harbor API integration', () => {
    const manualDigest = `sha256:${'a'.repeat(64)}`;
    const webhookDigest = `sha256:${'b'.repeat(64)}`;
    const authenticatedUser = {
        id: 'user-1',
        organizationId: 'org-1',
        roles: [{ role: 'DEVELOPER', scope: 'ORGANIZATION', scopeId: 'org-1' }],
    };
    const settings = {
        enabled: true,
        baseUrl: 'https://harbor.example.test',
        username: 'robot$jasca',
        password: 'registry-password',
        allowedProjects: ['platform'],
        defaultProjectId: 'jasca-project',
        webhookSecret: 'webhook-secret',
        autoScanOnPush: true,
    };

    let app: INestApplication;
    let baseUrl: string;
    let scanImageReference: jest.Mock;
    let uploadScan: jest.Mock;
    let persistedScans: Array<Record<string, any>>;

    beforeAll(async () => {
        const jobs = new Map<string, Record<string, any>>();
        persistedScans = [];
        scanImageReference = jest.fn(async (imageRef: string) => ({
            rawResult: {
                SchemaVersion: 2,
                ArtifactName: imageRef,
                Metadata: {},
                Results: [],
            },
        }));
        uploadScan = jest.fn(async (
            projectId: string,
            uploadDto: Record<string, any>,
            rawResult: Record<string, any>,
            sourceInfo: Record<string, any>,
            currentUser?: Record<string, any>,
        ) => {
            const scan = {
                id: `scan-${persistedScans.length + 1}`,
                projectId,
                uploadDto,
                rawResult,
                sourceInfo,
                currentUser,
            };
            persistedScans.push(scan);
            return { id: scan.id };
        });

        const matchesWhere = (job: Record<string, any>, where: Record<string, any>): boolean =>
            Object.entries(where).every(([field, expected]) => {
                if (field === 'OR') {
                    return (expected as Array<Record<string, any>>)
                        .some((condition) => matchesWhere(job, condition));
                }
                if (expected && typeof expected === 'object' && 'lte' in expected) {
                    return job[field] instanceof Date
                        && job[field].getTime() <= (expected as { lte: Date }).lte.getTime();
                }
                return job[field] === expected;
            });

        const prisma = {
            project: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'jasca-project',
                    organizationId: 'org-1',
                }),
            },
            harborScanJob: {
                create: jest.fn(async ({ data }: { data: Record<string, any> }) => {
                    const key = `${data.projectId}:${data.imageDigest}`;
                    if (jobs.has(key)) {
                        throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
                    }
                    jobs.set(key, { id: `job-${jobs.size + 1}`, ...data });
                    return { id: jobs.get(key)!.id };
                }),
                updateMany: jest.fn(async ({ where, data }: {
                    where: Record<string, any>;
                    data: Record<string, any>;
                }) => {
                    let count = 0;
                    for (const job of jobs.values()) {
                        if (matchesWhere(job, where)) {
                            Object.assign(job, data);
                            count += 1;
                        }
                    }
                    return { count };
                }),
            },
        };

        const moduleRef = await Test.createTestingModule({
            controllers: [HarborController, HarborWebhookController],
            providers: [
                HarborScanService,
                RolesGuard,
                { provide: HarborService, useValue: {} },
                { provide: SettingsService, useValue: { getRaw: jest.fn().mockResolvedValue(settings) } },
                { provide: TrivyScanService, useValue: { scanImageReference } },
                { provide: ScansService, useValue: { uploadScan } },
                { provide: PrismaService, useValue: prisma },
            ],
        })
            .overrideGuard(JwtAuthGuard)
            .useValue({
                canActivate(context: ExecutionContext) {
                    const request = context.switchToHttp().getRequest();
                    if (request.headers.authorization !== 'Bearer valid-jwt') {
                        throw new UnauthorizedException('Invalid test JWT');
                    }
                    request.user = authenticatedUser;
                    return true;
                },
            })
            .compile();

        app = moduleRef.createNestApplication();
        app.setGlobalPrefix('api');
        await app.listen(0, '127.0.0.1');
        const address = app.getHttpServer().address();
        baseUrl = `http://127.0.0.1:${address.port}/api/harbor`;
    });

    afterAll(async () => {
        await app.close();
    });

    it('persists authenticated manual and authorized push scans, deduplicates by digest, and rejects invalid auth', async () => {
        const manualResponse = await fetch(`${baseUrl}/scan`, {
            method: 'POST',
            headers: {
                Authorization: 'Bearer valid-jwt',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                projectId: 'jasca-project',
                imageRef: 'harbor.example.test/platform/backend:latest',
                imageDigest: manualDigest,
                tag: 'latest',
            }),
        });

        expect(manualResponse.status).toBe(201);
        await expect(manualResponse.json()).resolves.toEqual({
            duplicate: false,
            scan: { id: 'scan-1' },
        });
        expect(persistedScans[0]).toEqual(expect.objectContaining({
            projectId: 'jasca-project',
            sourceInfo: expect.objectContaining({ uploadedById: 'user-1' }),
            currentUser: authenticatedUser,
            rawResult: expect.objectContaining({
                Metadata: expect.objectContaining({
                    JascaScanEvidence: expect.objectContaining({
                        harbor: expect.objectContaining({ trigger: 'manual', imageDigest: manualDigest }),
                    }),
                }),
            }),
        }));

        const webhookPayload = {
            type: 'PUSH_ARTIFACT',
            event_data: {
                resources: [{
                    digest: webhookDigest,
                    tag: 'stable',
                    resource_url: 'harbor.example.test/platform/backend:stable',
                }],
                repository: {
                    name: 'backend',
                    namespace: 'platform',
                    repo_full_name: 'platform/backend',
                },
            },
        };
        const sendWebhook = (authorization: string) => fetch(`${baseUrl}/webhook`, {
            method: 'POST',
            headers: {
                Authorization: authorization,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(webhookPayload),
        });

        const webhookResponse = await sendWebhook('Bearer webhook-secret');
        expect(webhookResponse.status).toBe(201);
        await expect(webhookResponse.json()).resolves.toEqual({ accepted: true });
        expect(persistedScans[1]).toEqual(expect.objectContaining({
            projectId: 'jasca-project',
            sourceInfo: expect.not.objectContaining({ uploadedById: expect.anything() }),
            rawResult: expect.objectContaining({
                Metadata: expect.objectContaining({
                    JascaScanEvidence: expect.objectContaining({
                        harbor: expect.objectContaining({ trigger: 'webhook', imageDigest: webhookDigest }),
                    }),
                }),
            }),
        }));

        const duplicateResponse = await sendWebhook('Bearer webhook-secret');
        expect(duplicateResponse.status).toBe(201);
        await expect(duplicateResponse.json()).resolves.toEqual({ accepted: true, duplicate: true });
        expect(scanImageReference).toHaveBeenCalledTimes(2);
        expect(uploadScan).toHaveBeenCalledTimes(2);
        expect(persistedScans).toHaveLength(2);

        const invalidWebhookResponse = await sendWebhook('Bearer wrong-secret');
        expect(invalidWebhookResponse.status).toBe(401);
        expect(scanImageReference).toHaveBeenCalledTimes(2);
        expect(uploadScan).toHaveBeenCalledTimes(2);

        const invalidManualResponse = await fetch(`${baseUrl}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                projectId: 'jasca-project',
                imageRef: 'harbor.example.test/platform/backend:latest',
                imageDigest: manualDigest,
            }),
        });
        expect(invalidManualResponse.status).toBe(401);
    });
});
