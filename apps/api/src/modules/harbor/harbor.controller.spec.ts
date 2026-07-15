import { HarborController } from './harbor.controller';

describe('HarborController', () => {
    it('sanitizes manual scan input and passes the authenticated user to the scan service', async () => {
        const harborService = {};
        const harborScanService = {
            scan: jest.fn().mockResolvedValue({ duplicate: false, scan: { id: 'scan-1' } }),
        };
        const controller = new (HarborController as any)(harborService, harborScanService);
        const user = {
            id: 'authenticated-user',
            organizationId: 'org-1',
            roles: [{ role: 'DEVELOPER' }],
        };

        await controller.scan({
            projectId: 'project-1',
            imageRef: 'harbor.example.test/platform/backend:latest',
            imageDigest: `sha256:${'a'.repeat(64)}`,
            tag: 'latest',
            requestedById: 'impersonated-user',
        }, user);

        expect(harborScanService.scan).toHaveBeenCalledWith({
            projectId: 'project-1',
            imageRef: 'harbor.example.test/platform/backend:latest',
            imageDigest: `sha256:${'a'.repeat(64)}`,
            tag: 'latest',
        }, user);
    });
});
