import { ServiceUnavailableException } from '@nestjs/common';
import { TrivyScanService } from './trivy-scan.service';

describe('TrivyScanService image references', () => {
    const imageDigest = `sha256:${'a'.repeat(64)}`;
    const imageRef = `harbor.example.test/platform/backend@${imageDigest}`;

    function createService() {
        const service = new TrivyScanService({
            get: jest.fn().mockResolvedValue({
                severities: ['CRITICAL', 'HIGH'],
                ignoreUnfixed: false,
                timeout: '5m',
                cacheDir: '/var/lib/trivy',
                scanners: ['vuln', 'license'],
            }),
        } as any);
        jest.spyOn((service as any).logger, 'log').mockImplementation();
        jest.spyOn((service as any).logger, 'error').mockImplementation();
        return service;
    }

    it('scans an immutable image reference in offline image mode with process-only credentials', async () => {
        const service = createService();
        const runTrivy = jest.spyOn(service as any, 'runTrivy').mockResolvedValue(JSON.stringify({
            SchemaVersion: 2,
            ArtifactName: imageRef,
            Results: [],
        }));

        const result = await service.scanImageReference(imageRef, {
            registryUsername: 'robot$jasca',
            registryPassword: 'registry-password',
        }, 'harbor-operation');

        expect(runTrivy).toHaveBeenCalledWith([
            'image',
            '--format',
            'json',
            '--cache-dir',
            '/var/lib/trivy',
            '--skip-db-update',
            '--skip-java-db-update',
            '--offline-scan',
            '--severity',
            'CRITICAL,HIGH',
            '--scanners',
            'vuln,license',
            '--timeout',
            '5m',
            imageRef,
        ], 5 * 60 * 1000, 'harbor-operation', {
            TRIVY_USERNAME: 'robot$jasca',
            TRIVY_PASSWORD: 'registry-password',
        });
        expect(result.rawResult.Metadata.JascaScanEvidence).toEqual(expect.objectContaining({
            scanMode: 'image',
            targetKind: 'container-image-reference',
        }));
        expect(JSON.stringify(result.rawResult.Metadata.JascaScanEvidence)).not.toContain('registry-password');
        expect(JSON.stringify(result.rawResult.Metadata.JascaScanEvidence)).not.toContain('robot$jasca');
    });

    it('redacts registry credentials from Trivy process failures', async () => {
        const service = createService();
        jest.spyOn(service as any, 'runTrivy').mockRejectedValue(Object.assign(
            new Error('authentication failed for robot$jasca using registry-password'),
            { stderr: 'registry-password is invalid for robot$jasca' },
        ));

        const promise = service.scanImageReference(imageRef, {
            registryUsername: 'robot$jasca',
            registryPassword: 'registry-password',
        });

        await expect(promise).rejects.toBeInstanceOf(ServiceUnavailableException);
        await expect(promise).rejects.not.toThrow(/registry-password|robot\$jasca/);
    });

    it('explicitly clears inherited registry credentials when none are configured', async () => {
        const service = createService();
        const runTrivy = jest.spyOn(service as any, 'runTrivy').mockResolvedValue(JSON.stringify({
            SchemaVersion: 2,
            ArtifactName: imageRef,
            Results: [],
        }));

        await service.scanImageReference(imageRef);

        const processEnv = runTrivy.mock.calls[0][3];
        expect(Object.prototype.hasOwnProperty.call(processEnv, 'TRIVY_USERNAME')).toBe(true);
        expect(Object.prototype.hasOwnProperty.call(processEnv, 'TRIVY_PASSWORD')).toBe(true);
        expect(processEnv).toEqual({
            TRIVY_USERNAME: undefined,
            TRIVY_PASSWORD: undefined,
        });
    });
});
