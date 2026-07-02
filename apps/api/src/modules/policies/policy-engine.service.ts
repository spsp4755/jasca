import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { Environment as PolicyEnvironment, Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { RequestUser, assertProjectAccess } from '../../common/authz/access-control';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

// Local type definitions for policy-related types
interface PolicyRuleType {
    id: string;
    ruleType: string;
    conditions: any;
    action: string;
    message: string | null;
    sendNotification?: boolean;
}

interface PolicyExceptionType {
    id: string;
    exceptionType: string;
    targetValue: string;
    status: string;
    expiresAt: Date | null;
}

type PolicyWithEvaluationRelations = Prisma.PolicyGetPayload<{
    include: {
        rules: true;
        exceptions: true;
    };
}>;

export interface PolicyViolation {
    policyId: string;
    policyName: string;
    ruleId: string;
    ruleName: string;
    action: string;
    message?: string;
    severity: Severity;
    count: number;
    cveIds: string[];
    sendNotification: boolean;
}

export interface PolicyEvaluation {
    allowed: boolean;
    blockedBy?: { policyId: string; policyName: string; ruleId: string };
    violations: PolicyViolation[];
    warnings: PolicyViolation[];
    appliedExceptions: PolicyExceptionType[];
}

@Injectable()
export class PolicyEngineService {
    constructor(private readonly prisma: PrismaService) { }

    /**
     * Evaluate policies against a scan result
     * @param projectId - Project ID
     * @param scanResultId - Scan result to evaluate
     * @param environment - Optional environment filter (Phase 2)
     */
    async evaluate(
        projectId: string,
        scanResultId: string,
        environment?: PolicyEnvironment,
        currentUser?: RequestUser,
    ): Promise<PolicyEvaluation> {
        // Get project and organization
        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            include: { organization: true },
        });

        if (!project) {
            throw new NotFoundException('Project not found');
        }

        if (currentUser) {
            assertProjectAccess(currentUser, project);
        }

        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            select: { projectId: true },
        });

        if (!scan) {
            throw new NotFoundException('Scan result not found');
        }

        if (scan.projectId !== projectId) {
            throw new BadRequestException('Scan result does not belong to the specified project');
        }

        // Get applicable policies (project-level and org-level)
        // Filter by environment if specified (Phase 2)
        const environmentFilter: Prisma.PolicyWhereInput = environment
            ? { OR: [{ environment }, { environment: PolicyEnvironment.ALL }] }
            : {};

        const policies: PolicyWithEvaluationRelations[] = await this.prisma.policy.findMany({
            where: {
                isActive: true,
                AND: [
                    environmentFilter,
                    {
                        OR: [
                            { projectId },
                            { organizationId: project.organizationId, projectId: null },
                        ],
                    },
                ],
            },
            include: {
                rules: { orderBy: { priority: 'desc' } },
                exceptions: {
                    where: {
                        status: 'APPROVED',
                        OR: [
                            { expiresAt: null },
                            { expiresAt: { gt: new Date() } },
                        ],
                    },
                },
            },
        });

        // Get scan vulnerabilities
        const scanVulns = await this.prisma.scanVulnerability.findMany({
            where: { scanResultId },
            include: { vulnerability: true },
        });

        const result: PolicyEvaluation = {
            allowed: true,
            violations: [],
            warnings: [],
            appliedExceptions: [],
        };

        // Evaluate each policy
        for (const policy of policies) {
            for (const rule of policy.rules) {
                const matchedVulns = this.evaluateRule(rule, scanVulns, policy.exceptions);

                if (matchedVulns.length > 0) {
                    const violation: PolicyViolation = {
                        policyId: policy.id,
                        policyName: policy.name,
                        ruleId: rule.id,
                        ruleName: `${policy.name} - ${rule.ruleType}`,
                        action: rule.action,
                        message: rule.message || undefined,
                        severity: this.getPrimarySeverity(matchedVulns),
                        count: matchedVulns.length,
                        cveIds: matchedVulns.map((v) => v.vulnerability.cveId),
                        sendNotification: Boolean(rule.sendNotification),
                    };

                    if (rule.action === 'BLOCK') {
                        result.violations.push(violation);
                        result.allowed = false;
                        if (!result.blockedBy) {
                            result.blockedBy = {
                                policyId: policy.id,
                                policyName: policy.name,
                                ruleId: rule.id,
                            };
                        }
                    } else if (rule.action === 'WARN') {
                        result.warnings.push(violation);
                    }
                }
            }

            // Track applied exceptions
            result.appliedExceptions.push(...policy.exceptions);
        }

        return result;
    }

    private evaluateRule(
        rule: PolicyRuleType,
        vulns: Array<{
            pkgName: string;
            pkgVersion: string;
            fixedVersion?: string | null;
            vulnerability: {
                cveId: string;
                severity: Severity;
                cvssV3Score?: number | null;
                publishedAt?: Date | null;
            };
        }>,
        exceptions: PolicyExceptionType[],
    ) {
        const conditions = rule.conditions as any;

        let filtered = vulns.filter((v) => !this.isExcepted(v, exceptions));

        switch (rule.ruleType) {
            case 'SEVERITY_THRESHOLD':
                if (conditions.severity) {
                    const targetSeverities = Array.isArray(conditions.severity)
                        ? conditions.severity
                        : [conditions.severity];
                    filtered = filtered.filter((v) =>
                        targetSeverities.includes(v.vulnerability.severity),
                    );
                }
                break;

            case 'CVSS_THRESHOLD':
                if (conditions.cvssScore?.gte !== undefined) {
                    filtered = filtered.filter(
                        (v) =>
                            v.vulnerability.cvssV3Score != null &&
                            v.vulnerability.cvssV3Score >= conditions.cvssScore.gte,
                    );
                }
                break;

            case 'CVE_BLOCKLIST':
                if (conditions.cveIds) {
                    const blockedCves = new Set(
                        (conditions.cveIds as string[]).map((cveId) => cveId.toUpperCase()),
                    );
                    filtered = filtered.filter((v) => blockedCves.has(v.vulnerability.cveId.toUpperCase()));
                } else if (conditions.cvePatterns) {
                    filtered = filtered.filter((v) =>
                        this.matchesAnyPattern(v.vulnerability.cveId, conditions.cvePatterns, conditions.patternMode),
                    );
                } else {
                    filtered = [];
                }
                break;

            case 'PACKAGE_BLOCKLIST':
                if (conditions.packageNames) {
                    const packageNames = new Set(
                        (conditions.packageNames as string[]).map((pkgName) => pkgName.toLowerCase()),
                    );
                    filtered = filtered.filter((v) => packageNames.has(v.pkgName.toLowerCase()));
                } else if (conditions.packagePatterns) {
                    filtered = filtered.filter((v) =>
                        this.matchesAnyPattern(v.pkgName, conditions.packagePatterns, conditions.patternMode),
                    );
                } else {
                    filtered = [];
                }
                break;

            case 'CVE_AGE':
                if (conditions.cveAge?.days !== undefined) {
                    const maxPublishedAt = new Date();
                    maxPublishedAt.setDate(maxPublishedAt.getDate() - Number(conditions.cveAge.days));
                    filtered = filtered.filter((v) =>
                        !!v.vulnerability.publishedAt && v.vulnerability.publishedAt <= maxPublishedAt,
                    );
                } else {
                    filtered = [];
                }
                break;

            default:
                filtered = [];
        }

        return filtered;
    }

    private isExcepted(
        vuln: {
            pkgName: string;
            vulnerability: { cveId: string; severity: Severity };
        },
        exceptions: PolicyExceptionType[],
    ): boolean {
        return exceptions.some((exception) => {
            const targetValue = exception.targetValue.toLowerCase();
            switch (exception.exceptionType) {
                case 'CVE':
                    return vuln.vulnerability.cveId.toLowerCase() === targetValue;
                case 'PACKAGE':
                    return vuln.pkgName.toLowerCase() === targetValue;
                case 'SEVERITY':
                    return vuln.vulnerability.severity.toLowerCase() === targetValue;
                default:
                    return false;
            }
        });
    }

    private matchesAnyPattern(value: string, patterns: string[], mode?: string): boolean {
        return patterns.some((pattern) => {
            if (mode === 'REGEX') {
                try {
                    return new RegExp(pattern, 'i').test(value);
                } catch {
                    return false;
                }
            }

            return value.toLowerCase().includes(String(pattern).toLowerCase());
        });
    }

    private getPrimarySeverity(
        vulns: Array<{ vulnerability: { severity: Severity } }>,
    ): Severity {
        const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

        for (const severity of order) {
            if (vulns.some((v) => v.vulnerability.severity === severity)) {
                return severity;
            }
        }

        return 'UNKNOWN';
    }
}
