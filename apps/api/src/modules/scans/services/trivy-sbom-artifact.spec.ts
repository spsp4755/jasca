import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ScanArtifactService } from './scan-artifact.service';
import { TrivyScanService } from './trivy-scan.service';

describe('Trivy Syft artifact flow', () => {
    it('returns the generated CycloneDX document with the Trivy result', async () => {
        const service = new TrivyScanService({} as any);
        const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'jasca-sbom-test-'));
        const targetPath = path.join(tempDir, 'target.tar');
        await fs.promises.writeFile(targetPath, 'target');
        const sbom = '{"bomFormat":"CycloneDX","specVersion":"1.5"}';
        jest.spyOn(service as any, 'runSyft').mockResolvedValue(sbom);
        jest.spyOn(service as any, 'runTrivy').mockResolvedValue('{"Results":[]}');

        try {
            await expect((service as any).runSyftThenTrivySbom(
                { scanners: ['vuln'], severities: ['HIGH'], ignoreUnfixed: false, timeout: '5m', cacheDir: '/tmp' },
                { mode: 'fs', targetPath },
                {},
                1000,
                'operation-1',
                [],
            )).resolves.toEqual({
                stdout: '{"Results":[]}',
                generatedSbom: sbom,
            });
        } finally {
            await fs.promises.rm(tempDir, { recursive: true, force: true });
        }
    });

    it('persists the exact SBOM with its hash and generator version', async () => {
        const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'jasca-artifact-test-'));
        const previousDir = process.env.SCAN_RESULT_DIR;
        process.env.SCAN_RESULT_DIR = tempDir;
        const prisma = {
            scanArtifact: {
                upsert: jest.fn().mockImplementation(({ create }) => ({ id: 'artifact-1', ...create })),
            },
        } as any;
        const clustara = { queueAutomatic: jest.fn().mockResolvedValue([]) } as any;
        const service = new ScanArtifactService(prisma, clustara);
        const sbom = JSON.stringify({
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            metadata: { tools: { components: [{ name: 'syft', version: '1.46.0' }] } },
        });

        try {
            const artifact = await service.persistCycloneDx('scan-1', sbom);
            const filePath = path.join(tempDir, 'artifacts', 'scan-1.cdx.json');
            await expect(fs.promises.readFile(filePath, 'utf-8')).resolves.toBe(sbom);
            expect(prisma.scanArtifact.upsert).toHaveBeenCalledWith(expect.objectContaining({
                create: expect.objectContaining({
                    scanResultId: 'scan-1',
                    filePath,
                    sha256: crypto.createHash('sha256').update(sbom).digest('hex'),
                    generator: 'syft',
                    generatorVersion: '1.46.0',
                }),
            }));
            expect(artifact.id).toBe('artifact-1');
            expect(clustara.queueAutomatic).toHaveBeenCalledWith('scan-1');
        } finally {
            if (previousDir === undefined) delete process.env.SCAN_RESULT_DIR;
            else process.env.SCAN_RESULT_DIR = previousDir;
            await fs.promises.rm(tempDir, { recursive: true, force: true });
        }
    });

    it('deletes persisted artifact files when a scan is removed', async () => {
        const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'jasca-artifact-delete-'));
        const filePath = path.join(tempDir, 'scan-1.cdx.json');
        await fs.promises.writeFile(filePath, '{}');
        const prisma = {
            scanArtifact: {
                findMany: jest.fn().mockResolvedValue([{ filePath }]),
            },
        } as any;
        const service = new ScanArtifactService(prisma, {} as any);

        try {
            await service.deleteForScan('scan-1');
            await expect(fs.promises.access(filePath)).rejects.toThrow();
        } finally {
            await fs.promises.rm(tempDir, { recursive: true, force: true });
        }
    });
});
