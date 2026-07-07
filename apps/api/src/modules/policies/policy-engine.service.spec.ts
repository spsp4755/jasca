import { NotFoundException } from '@nestjs/common';
import { PolicyEngineService, PolicyEvaluation } from './policy-engine.service';

describe('PolicyEngineService.verdict', () => {
    const passingEvaluation: PolicyEvaluation = {
        allowed: true,
        violations: [],
        warnings: [],
        appliedExceptions: [],
    };

    const failingEvaluation: PolicyEvaluation = {
        allowed: false,
        blockedBy: { policyId: 'p1', policyName: 'No criticals', ruleId: 'r1' },
        violations: [
            {
                policyId: 'p1',
                policyName: 'No criticals',
                ruleId: 'r1',
                ruleName: 'block-critical',
                action: 'BLOCK',
                severity: 'CRITICAL',
                count: 2,
                cveIds: ['CVE-2024-0001'],
                sendNotification: false,
            },
        ],
        warnings: [],
        appliedExceptions: [],
    };

    function buildService(evaluation: PolicyEvaluation, prismaOverrides: any = {}) {
        const prisma: any = {
            scanResult: {
                findFirst: jest.fn().mockResolvedValue({ id: 'scan-latest', scannedAt: new Date('2026-07-07') }),
                findUnique: jest.fn().mockResolvedValue({ scannedAt: new Date('2026-07-01') }),
                ...prismaOverrides,
            },
        };
        const service = new PolicyEngineService(prisma);
        jest.spyOn(service, 'evaluate').mockResolvedValue(evaluation);
        return { service, prisma };
    }

    it('returns PASS with the latest scan when no scanResultId is given', async () => {
        const { service, prisma } = buildService(passingEvaluation);

        const result = await service.verdict('project-1');

        expect(result.verdict).toBe('PASS');
        expect(result.scanResultId).toBe('scan-latest');
        expect(prisma.scanResult.findFirst).toHaveBeenCalledWith(
            expect.objectContaining({ where: { projectId: 'project-1' } }),
        );
        expect(service.evaluate).toHaveBeenCalledWith('project-1', 'scan-latest', undefined, undefined);
    });

    it('returns FAIL with violations when evaluation blocks', async () => {
        const { service } = buildService(failingEvaluation);

        const result = await service.verdict('project-1', 'scan-42');

        expect(result.verdict).toBe('FAIL');
        expect(result.scanResultId).toBe('scan-42');
        expect(result.blockedBy?.policyName).toBe('No criticals');
        expect(result.violations).toHaveLength(1);
    });

    it('throws when the project has no scans', async () => {
        const { service } = buildService(passingEvaluation, {
            findFirst: jest.fn().mockResolvedValue(null),
        });

        await expect(service.verdict('empty-project')).rejects.toThrow(NotFoundException);
    });
});
