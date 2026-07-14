import {
    buildClustaraRequest,
    ClustaraService,
    deriveClustaraScanner,
    deriveImageDigest,
    isRetryableFailure,
    normalizeClustaraSettings,
    sanitizeClustaraSettings,
} from './clustara.service';
import { createServer } from 'http';

describe('Clustara integration contract', () => {
    it('normalizes safe closed-network defaults', () => {
        expect(normalizeClustaraSettings({})).toEqual(expect.objectContaining({
            enabled: false,
            autoSend: false,
            scanPath: '/admin/k8s/security/scans/import',
            sbomPath: '/admin/k8s/security/sboms',
            authType: 'NONE',
            scanner: 'trivy',
            generator: 'syft',
            timeoutSeconds: 30,
            maxAttempts: 3,
            verifyTls: true,
        }));
    });

    it('does not return the stored credential', () => {
        const safe = sanitizeClustaraSettings(normalizeClustaraSettings({
            authType: 'X_API_KEY',
            credential: 'internal-secret',
        }));

        expect(safe).not.toHaveProperty('credential');
        expect(safe.credentialConfigured).toBe(true);
    });

    it.each([
        ['NONE', undefined, undefined],
        ['X_API_KEY', 'internal-secret', undefined],
        ['BEARER', undefined, 'Bearer internal-secret'],
    ] as const)('builds %s authentication headers', (authType, apiKey, authorization) => {
        const request = buildClustaraRequest(
            normalizeClustaraSettings({
                baseUrl: 'https://clustara.internal/',
                authType,
                credential: authType === 'NONE' ? '' : 'internal-secret',
            }),
            'TRIVY',
            {
                clusterId: 'prod cluster',
                imageDigest: `sha256:${'a'.repeat(64)}`,
                scanner: 'trivy/internal',
            },
        );

        expect(request.url.toString()).toBe(
            `https://clustara.internal/admin/k8s/security/scans/import?cluster_id=prod+cluster&scanner=trivy%2Finternal&image_digest=sha256%3A${'a'.repeat(64)}`,
        );
        expect(request.headers['X-API-Key']).toBe(apiKey);
        expect(request.headers.Authorization).toBe(authorization);
        expect(request.headers['Content-Type']).toBe('application/json');
    });

    it('builds the configurable SBOM endpoint', () => {
        const request = buildClustaraRequest(
            normalizeClustaraSettings({
                baseUrl: 'http://clustara:8085/base',
                sbomPath: '/custom/sboms',
            }),
            'SBOM',
            {
                clusterId: 'unused',
                imageDigest: `sha256:${'b'.repeat(64)}`,
                generator: 'syft 1.46',
            },
        );

        expect(request.url.toString()).toBe(
            `http://clustara:8085/custom/sboms?image_digest=sha256%3A${'b'.repeat(64)}&generator=syft+1.46`,
        );
    });

    it('uses an image reference for scan and SBOM imports when a digest is unavailable', () => {
        const settings = normalizeClustaraSettings({ baseUrl: 'https://clustara.internal' });
        const input = {
            clusterId: 'prod',
            imageDigest: '',
            imageRef: 'registry.internal/team/api:1.2.3',
            scanner: 'semgrep',
            generator: 'syft',
        };

        expect(buildClustaraRequest(settings, 'TRIVY', input).url.toString()).toBe(
            'https://clustara.internal/admin/k8s/security/scans/import?cluster_id=prod&scanner=semgrep&image=registry.internal%2Fteam%2Fapi%3A1.2.3',
        );
        expect(buildClustaraRequest(settings, 'SBOM', input).url.toString()).toBe(
            'https://clustara.internal/admin/k8s/security/sboms?image=registry.internal%2Fteam%2Fapi%3A1.2.3&generator=syft',
        );
    });

    it('derives an OCI digest in explicit, RepoDigests, then ImageID order', () => {
        const repoDigest = `sha256:${'b'.repeat(64)}`;
        const imageId = `sha256:${'c'.repeat(64)}`;

        expect(deriveImageDigest(`sha256:${'a'.repeat(64)}`, {
            Metadata: { RepoDigests: [`repo@${repoDigest}`], ImageID: imageId },
        })).toBe(`sha256:${'a'.repeat(64)}`);
        expect(deriveImageDigest(undefined, {
            Metadata: { RepoDigests: [`repo@${repoDigest}`], ImageID: imageId },
        })).toBe(repoDigest);
        expect(deriveImageDigest(undefined, { Metadata: { ImageID: imageId } })).toBe(imageId);
        expect(deriveImageDigest('sha256:short', {})).toBeUndefined();
    });

    it.each([
        [{ sourceType: 'CHECKOV_JSON' }, 'checkov'],
        [{ sourceType: 'ZAP_JSON' }, 'zap'],
        [{ sourceType: 'SARIF', rawResult: { Metadata: { JascaScanEvidence: { scanner: 'semgrep' } } } }, 'semgrep'],
        [{ sourceType: 'TRIVY_JSON' }, 'trivy'],
    ])('derives the correct scanner identifier for %o', (scan, expected) => {
        expect(deriveClustaraScanner(scan)).toBe(expected);
    });

    it.each([
        [408, true],
        [429, true],
        [500, true],
        [503, true],
        [400, false],
        [401, false],
        [404, false],
        [undefined, true],
    ])('classifies HTTP %s retryability', (status, expected) => {
        expect(isRetryableFailure(status)).toBe(expected);
    });
});

describe('ClustaraService', () => {
    it('exposes only non-secret scan options to project users', async () => {
        const settingsStore = {
            getRaw: jest.fn().mockResolvedValue({
                enabled: true,
                baseUrl: 'https://private.internal',
                credential: 'secret',
                defaultClusterId: 'prod',
                scanner: 'internal-trivy',
                generator: 'internal-syft',
            }),
        } as any;
        const service = new ClustaraService({} as any, settingsStore);

        await expect(service.getPublicOptions()).resolves.toEqual({
            enabled: true,
            defaultClusterId: 'prod',
            scanner: 'internal-trivy',
            generator: 'internal-syft',
        });
    });

    it('preserves a stored credential when an update leaves it blank', async () => {
        const settingsStore = {
            getRaw: jest.fn().mockResolvedValue({
                baseUrl: 'https://old.internal',
                authType: 'X_API_KEY',
                credential: 'stored-secret',
            }),
            set: jest.fn().mockResolvedValue(undefined),
        } as any;
        const service = new ClustaraService({} as any, settingsStore);

        const result = await service.updateSettings({
            baseUrl: 'https://new.internal/',
            authType: 'X_API_KEY',
            credential: '',
        });

        expect(settingsStore.set).toHaveBeenCalledWith('clustara', expect.objectContaining({
            baseUrl: 'https://new.internal',
            credential: 'stored-secret',
        }));
        expect(result).not.toHaveProperty('credential');
        expect(result.credentialConfigured).toBe(true);
    });

    it('sends the exact JSON body to a configurable internal endpoint', async () => {
        let received: { url?: string; apiKey?: string; body?: string } = {};
        const server = createServer((request, response) => {
            const chunks: Buffer[] = [];
            request.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
            request.on('end', () => {
                received = {
                    url: request.url,
                    apiKey: String(request.headers['x-api-key'] || ''),
                    body: Buffer.concat(chunks).toString('utf-8'),
                };
                response.statusCode = 201;
                response.end('{"imported":true}');
            });
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

        try {
            const address = server.address();
            if (!address || typeof address === 'string') throw new Error('test server did not bind');
            const settings = normalizeClustaraSettings({
                baseUrl: `http://127.0.0.1:${address.port}`,
                authType: 'X_API_KEY',
                credential: 'internal-secret',
                timeoutSeconds: 5,
            });
            const service = new ClustaraService({} as any, {} as any);
            const body = '{"SchemaVersion":2,"Results":[]}';
            const result = await service.sendPayload(settings, 'TRIVY', {
                clusterId: 'prod',
                scanner: 'trivy',
                imageDigest: `sha256:${'d'.repeat(64)}`,
            }, body);

            expect(result).toEqual({ status: 201, body: '{"imported":true}' });
            expect(received).toEqual({
                url: `/admin/k8s/security/scans/import?cluster_id=prod&scanner=trivy&image_digest=sha256%3A${'d'.repeat(64)}`,
                apiKey: 'internal-secret',
                body,
            });
        } finally {
            await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
        }
    });

    it('queues a scan using its target reference when a digest is unavailable', async () => {
        const prisma = {
            scanResult: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'scan-1',
                    imageRef: 'uploaded-policy.zip',
                    project: { id: 'project-1', organizationId: 'org-1' },
                    rawResult: {},
                    artifacts: [],
                }),
            },
            clustaraDelivery: { upsert: jest.fn().mockResolvedValue({ id: 'delivery-1' }) },
        } as any;
        const settingsStore = {
            getRaw: jest.fn().mockResolvedValue({ enabled: true, defaultClusterId: 'prod' }),
        } as any;
        const service = new ClustaraService(prisma, settingsStore);

        await expect(service.queueDelivery('scan-1', 'TRIVY', { clusterId: 'prod', scanner: 'zap' })).resolves.toEqual({ id: 'delivery-1' });
        expect(prisma.clustaraDelivery.upsert).toHaveBeenCalledWith(expect.objectContaining({
            where: { scanResultId_type_clusterId_imageDigest: {
                scanResultId: 'scan-1',
                type: 'TRIVY',
                clusterId: 'prod',
                imageDigest: 'uploaded-policy.zip',
            } },
            create: expect.objectContaining({ scanner: 'zap' }),
        }));
    });

    it('automatically queues a Checkov result with its uploaded target reference', async () => {
        const scan = {
            id: 'scan-checkov',
            sourceType: 'CHECKOV_JSON',
            imageRef: 'Dockerfile',
            rawResult: { results: { failed_checks: [] } },
            artifacts: [],
            project: { id: 'project-1', organizationId: 'org-1' },
        };
        const prisma = {
            scanResult: { findUnique: jest.fn().mockResolvedValue(scan) },
            clustaraDelivery: { upsert: jest.fn().mockResolvedValue({ id: 'delivery-checkov' }) },
        } as any;
        const service = new ClustaraService(prisma, {
            getRaw: jest.fn().mockResolvedValue({ enabled: true, autoSend: true, defaultClusterId: 'prod' }),
        } as any);

        await expect(service.queueAutomatic(scan.id)).resolves.toEqual([{ id: 'delivery-checkov' }]);
        expect(prisma.clustaraDelivery.upsert).toHaveBeenCalledWith(expect.objectContaining({
            create: expect.objectContaining({ scanner: 'checkov', imageDigest: 'Dockerfile' }),
        }));
    });

    it('rejects manual queue requests while the integration is disabled', async () => {
        const digest = `sha256:${'a'.repeat(64)}`;
        const prisma = {
            scanResult: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'scan-1',
                    imageDigest: digest,
                    project: { id: 'project-1', organizationId: 'org-1' },
                    rawResult: {},
                    artifacts: [],
                }),
            },
            clustaraDelivery: { create: jest.fn() },
        } as any;
        const service = new ClustaraService(prisma, {
            getRaw: jest.fn().mockResolvedValue({ enabled: false, defaultClusterId: 'prod' }),
        } as any);

        await expect(service.queueDelivery('scan-1', 'TRIVY', {})).rejects.toThrow('비활성화');
        expect(prisma.clustaraDelivery.create).not.toHaveBeenCalled();
    });

    it('rejects retry access from a different organization', async () => {
        const prisma = {
            clustaraDelivery: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'delivery-1',
                    scanResult: { project: { id: 'project-1', organizationId: 'org-1' } },
                }),
                update: jest.fn(),
            },
        } as any;
        const service = new ClustaraService(prisma, {} as any);

        await expect(service.retryDelivery('delivery-1', {
            id: 'user-2',
            organizationId: 'org-2',
            roles: [{ role: 'PROJECT_ADMIN', scope: 'PROJECT', scopeId: 'project-2' }],
        })).rejects.toThrow('access');
        expect(prisma.clustaraDelivery.update).not.toHaveBeenCalled();
    });

    it('allows a global security administrator to queue a project delivery', async () => {
        const digest = `sha256:${'e'.repeat(64)}`;
        const existing = { id: 'delivery-1', imageDigest: digest };
        const prisma = {
            scanResult: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'scan-1',
                    imageDigest: digest,
                    project: { id: 'project-1', organizationId: 'org-1' },
                    rawResult: {},
                    artifacts: [],
                }),
            },
            clustaraDelivery: { upsert: jest.fn().mockResolvedValue(existing) },
        } as any;
        const settingsStore = {
            getRaw: jest.fn().mockResolvedValue({ enabled: true, defaultClusterId: 'prod' }),
        } as any;
        const service = new ClustaraService(prisma, settingsStore);

        await expect(service.queueDelivery('scan-1', 'TRIVY', {}, {
            id: 'security-1',
            roles: [{ role: 'SECURITY_ADMIN', scope: 'GLOBAL' }],
        })).resolves.toBe(existing);
        expect(prisma.clustaraDelivery.upsert).toHaveBeenCalledWith(expect.objectContaining({
            where: { scanResultId_type_clusterId_imageDigest: {
                scanResultId: 'scan-1',
                type: 'TRIVY',
                clusterId: 'prod',
                imageDigest: digest,
            } },
            update: {},
        }));
    });
});
