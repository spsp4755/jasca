import { ComplianceService } from './compliance.service';

describe('ComplianceService', () => {
    function buildService(vulns: any[]) {
        const prisma: any = {
            scanVulnerability: { findMany: jest.fn().mockResolvedValue(vulns) },
        };
        return new ComplianceService(prisma);
    }

    it('aggregates vulnerabilities into OWASP Top 10 and CWE Top 25', async () => {
        const service = buildService([
            { vulnerability: { cveId: 'CVE-1', severity: 'CRITICAL', cweIds: ['CWE-89'] } }, // A03 + Top25 #3
            { vulnerability: { cveId: 'CVE-2', severity: 'HIGH', cweIds: ['CWE-79'] } }, // A03 + Top25 #1
            { vulnerability: { cveId: 'CVE-3', severity: 'MEDIUM', cweIds: ['CWE-798'] } }, // A07 + Top25 #22
            { vulnerability: { cveId: 'CVE-4', severity: 'LOW', cweIds: ['CWE-99999'] } }, // unmapped
            { vulnerability: { cveId: 'CVE-5', severity: 'HIGH', cweIds: [] } }, // unmapped
        ]);

        const report = await service.getComplianceReport('project-1');

        expect(report.totalOpenVulnerabilities).toBe(5);
        expect(report.unmappedCount).toBe(2);

        const a03 = report.owaspTop10.find((c) => c.id === 'A03');
        expect(a03?.count).toBe(2);
        expect(a03?.critical).toBe(1);
        expect(a03?.high).toBe(1);
        expect(a03?.cweIds).toEqual(expect.arrayContaining(['CWE-89', 'CWE-79']));

        const a07 = report.owaspTop10.find((c) => c.id === 'A07');
        expect(a07?.count).toBe(1);

        expect(report.cweTop25[0]).toMatchObject({ rank: 1, cweId: 'CWE-79', count: 1 });
        expect(report.cweTop25.map((c) => c.cweId)).toEqual(['CWE-79', 'CWE-89', 'CWE-798']);
    });

    it('does not double-count a vuln with multiple CWEs in the same category', async () => {
        const service = buildService([
            // CWE-89 and CWE-78 are both A03
            { vulnerability: { cveId: 'CVE-1', severity: 'HIGH', cweIds: ['CWE-89', 'CWE-78'] } },
        ]);

        const report = await service.getComplianceReport('project-1');
        const a03 = report.owaspTop10.find((c) => c.id === 'A03');
        expect(a03?.count).toBe(1);
    });

    it('returns remediation guidance for known CWEs only', () => {
        const service = buildService([]);
        const guidance = service.getRemediationGuidance(['CWE-89', '79', 'CWE-424242']);

        expect(guidance).toHaveLength(2);
        expect(guidance[0].cweId).toBe('CWE-89');
        expect(guidance[1].cweId).toBe('CWE-79');
        expect(guidance[0].guidance).toContain('바인딩');
    });
});
