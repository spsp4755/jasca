import { ScansService } from './scans.service';

describe('ScansService Clustara digest projection', () => {
    it('projects a valid Trivy Metadata ImageID when the DTO digest was absent', async () => {
        const digest = `sha256:${'f'.repeat(64)}`;
        const prisma = {
            scanResult: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'scan-1',
                    projectId: 'project-1',
                    project: { id: 'project-1', name: 'Project', organizationId: 'org-1', organization: { id: 'org-1', name: 'Org' } },
                    imageRef: 'internal/app:test',
                    imageDigest: null,
                    sourceType: 'TRIVY_JSON',
                    rawResult: { Metadata: { ImageID: digest } },
                    summary: null,
                    vulnerabilities: [],
                    artifacts: [],
                    scannedAt: new Date('2026-07-10T00:00:00Z'),
                    createdAt: new Date('2026-07-10T00:00:00Z'),
                }),
            },
        } as any;
        const service = new ScansService(
            prisma,
            {} as any, {} as any, {} as any, {} as any, {} as any, {} as any,
            {} as any, {} as any, {} as any, {} as any, {} as any,
        );

        await expect(service.findById('scan-1')).resolves.toEqual(expect.objectContaining({ imageDigest: digest }));
    });
});
