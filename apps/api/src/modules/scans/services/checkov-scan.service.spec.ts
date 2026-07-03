import { CheckovScanService } from './checkov-scan.service';

const checkovSettings = (allowInternalModuleDownload: boolean) => ({
    allowInternalModuleDownload,
});

describe('CheckovScanService', () => {
    it('forces external module downloads off for closed-network defaults', () => {
        const service = new CheckovScanService();
        const normalized = (service as any).normalizeScanOptions(
            {
                frameworks: ['terraform', 'kubernetes', 'invalid-framework'],
                checks: ['CKV_AWS_20', '  '],
                skipChecks: ['CKV_AWS_999'],
                downloadExternalModules: true,
                quiet: false,
                timeout: '15m',
            },
            checkovSettings(false),
        );

        expect(normalized).toEqual({
            frameworks: ['terraform', 'kubernetes'],
            checks: ['CKV_AWS_20'],
            skipChecks: ['CKV_AWS_999'],
            downloadExternalModules: false,
            quiet: false,
            timeout: '15m',
        });
    });

    it('allows Checkov external module download only when admin setting enables internal module repositories', () => {
        const service = new CheckovScanService();
        const normalized = (service as any).normalizeScanOptions(
            {},
            checkovSettings(true),
        );

        expect(normalized.downloadExternalModules).toBe(true);
    });

    it('builds Checkov args with json output and soft fail', () => {
        const service = new CheckovScanService();
        const args = (service as any).buildCheckovArgs({
            targetPath: '/tmp/jasca-checkov/source',
            inputKind: 'directory',
        }, {
            frameworks: ['terraform'],
            checks: ['CKV_AWS_20'],
            skipChecks: ['CKV_AWS_999'],
            downloadExternalModules: false,
            quiet: true,
            timeout: '10m',
        });

        expect(args).toContain('--output');
        expect(args).toContain('json');
        expect(args).toContain('--soft-fail');
        expect(args).toContain('--compact');
        expect(args).toContain('--framework');
        expect(args).toContain('terraform');
        expect(args).toContain('--check');
        expect(args).toContain('CKV_AWS_20');
        expect(args).toContain('--skip-check');
        expect(args).toContain('CKV_AWS_999');
        expect(args).toContain('--download-external-modules');
        expect(args).toContain('false');
        expect(args).toContain('-d');
        expect(args).toContain('/tmp/jasca-checkov/source');
    });
});
