import { NotFoundException } from '@nestjs/common';
import { ScansService } from './scans.service';

describe('ScansService.getBestFixes', () => {
    const vuln = (over: any) => ({
        pkgName: 'pkg-a',
        pkgVersion: '1.0.0',
        fixedVersion: null,
        status: 'OPEN',
        vulnerability: { cveId: 'CVE-1', severity: 'HIGH', title: 't' },
        ...over,
    });

    function buildService(vulnerabilities: any[]) {
        const prisma: any = {
            scanResult: {
                findUnique: jest.fn().mockResolvedValue({
                    id: 'scan-1',
                    project: { organization: {} },
                    vulnerabilities,
                }),
            },
        };
        // getBestFixes only touches prisma
        return new (ScansService as any)(prisma) as ScansService;
    }

    it('groups package upgrades and picks the highest fixed version', async () => {
        const service = buildService([
            vuln({ pkgName: 'lodash', fixedVersion: '4.17.21', vulnerability: { cveId: 'CVE-A', severity: 'CRITICAL', title: '' } }),
            vuln({ pkgName: 'lodash', fixedVersion: '4.17.12', vulnerability: { cveId: 'CVE-B', severity: 'MEDIUM', title: '' } }),
            vuln({ pkgName: 'lodash', fixedVersion: '4.17.9', vulnerability: { cveId: 'CVE-C', severity: 'HIGH', title: '' } }),
            vuln({ pkgName: 'express', fixedVersion: '5.0.0', vulnerability: { cveId: 'CVE-D', severity: 'LOW', title: '' } }),
        ]);

        const result = await service.getBestFixes('scan-1');

        expect(result.packageFixes[0]).toMatchObject({
            pkgName: 'lodash',
            recommendedVersion: '4.17.21', // numeric-aware: 21 > 12 > 9
            resolves: 3,
            critical: 1,
            topSeverity: 'CRITICAL',
        });
        expect(result.packageFixes[1].pkgName).toBe('express');
        expect(result.codeFixes).toEqual([]);
    });

    it('groups repeated code findings by rule and file, requiring 2+', async () => {
        const service = buildService([
            vuln({ pkgName: 'src/a.ts', pkgVersion: 'L10', vulnerability: { cveId: 'SEMGREP-sqli', severity: 'HIGH', title: 'SQLi' } }),
            vuln({ pkgName: 'src/a.ts', pkgVersion: 'L42', vulnerability: { cveId: 'SEMGREP-sqli', severity: 'HIGH', title: 'SQLi' } }),
            vuln({ pkgName: 'src/b.ts', pkgVersion: 'L7', vulnerability: { cveId: 'SEMGREP-sqli', severity: 'HIGH', title: 'SQLi' } }), // single -> excluded
        ]);

        const result = await service.getBestFixes('scan-1');

        expect(result.codeFixes).toHaveLength(1);
        expect(result.codeFixes[0]).toMatchObject({
            ruleId: 'SEMGREP-sqli',
            file: 'src/a.ts',
            resolves: 2,
            locations: ['L10', 'L42'],
        });
    });

    it('sorts by resolves count then severity', async () => {
        const service = buildService([
            vuln({ pkgName: 'small', fixedVersion: '2.0.0', vulnerability: { cveId: 'C1', severity: 'CRITICAL', title: '' } }),
            vuln({ pkgName: 'big', fixedVersion: '1.1.0', vulnerability: { cveId: 'C2', severity: 'LOW', title: '' } }),
            vuln({ pkgName: 'big', fixedVersion: '1.1.0', vulnerability: { cveId: 'C3', severity: 'LOW', title: '' } }),
        ]);

        const result = await service.getBestFixes('scan-1');
        expect(result.packageFixes.map((f) => f.pkgName)).toEqual(['big', 'small']);
    });

    it('throws for unknown scans', async () => {
        const prisma: any = { scanResult: { findUnique: jest.fn().mockResolvedValue(null) } };
        const service = new (ScansService as any)(prisma) as ScansService;
        await expect(service.getBestFixes('nope')).rejects.toThrow(NotFoundException);
    });
});
