import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface ComplianceReport {
    id: string;
    organizationId: string;
    reportType: 'PCI-DSS' | 'SOC2' | 'HIPAA' | 'ISO27001' | 'GENERAL';
    generatedAt: Date;
    summary: {
        totalVulnerabilities: number;
        criticalUnresolved: number;
        highUnresolved: number;
        meanTimeToResolve: number;
        complianceScore: number;
    };
    sections: ComplianceSection[];
}

interface ComplianceSection {
    title: string;
    status: 'PASS' | 'FAIL' | 'WARNING' | 'NOT_APPLICABLE';
    findings: string[];
    recommendations: string[];
}

export interface PolicyViolation {
    id: string;
    policyId: string;
    policyName: string;
    scanVulnerabilityId: string;
    cveId: string;
    severity: string;
    action: string;
    detectedAt: Date;
    resolvedAt?: Date;
}

@Injectable()
export class ComplianceService {
    private readonly logger = new Logger(ComplianceService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Generate compliance report for an organization
     */
    async generateComplianceReport(
        organizationId: string,
        reportType: ComplianceReport['reportType'] = 'GENERAL',
    ): Promise<ComplianceReport> {
        const org = await this.prisma.organization.findUnique({
            where: { id: organizationId },
            include: {
                projects: {
                    include: {
                        scanResults: {
                            orderBy: { createdAt: 'desc' },
                            take: 1,
                            include: {
                                vulnerabilities: {
                                    include: { vulnerability: true },
                                },
                            },
                        },
                    },
                },
            },
        });

        if (!org) {
            throw new Error('Organization not found');
        }

        let totalVulns = 0;
        let criticalUnresolved = 0;
        let highUnresolved = 0;

        for (const project of org.projects) {
            for (const scan of project.scanResults) {
                for (const sv of scan.vulnerabilities) {
                    totalVulns++;
                    const status = sv.status;
                    if (status !== 'FIXED' && status !== 'CLOSED') {
                        if (sv.vulnerability.severity === 'CRITICAL') criticalUnresolved++;
                        else if (sv.vulnerability.severity === 'HIGH') highUnresolved++;
                    }
                }
            }
        }

        // Calculate compliance score (simplified)
        const complianceScore = this.calculateComplianceScore(criticalUnresolved, highUnresolved, totalVulns);

        const sections = this.generateComplianceSections(reportType, criticalUnresolved, highUnresolved, org.projects.length);

        return {
            id: `report-${Date.now()}`,
            organizationId,
            reportType,
            generatedAt: new Date(),
            summary: {
                totalVulnerabilities: totalVulns,
                criticalUnresolved,
                highUnresolved,
                meanTimeToResolve: 0, // Would calculate from workflow history
                complianceScore,
            },
            sections,
        };
    }

    /**
     * Track policy violations
     */
    async trackPolicyViolations(scanResultId: string): Promise<PolicyViolation[]> {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: {
                project: {
                    include: {
                        policies: {
                            where: { isActive: true },
                            include: { rules: true },
                        },
                    },
                },
                vulnerabilities: {
                    include: { vulnerability: true },
                },
            },
        });

        if (!scan) return [];

        const violations: PolicyViolation[] = [];

        for (const policy of scan.project.policies) {
            for (const rule of policy.rules) {
                for (const sv of scan.vulnerabilities) {
                    if (this.isViolation(rule, sv.vulnerability)) {
                        violations.push({
                            id: `violation-${Date.now()}-${violations.length}`,
                            policyId: policy.id,
                            policyName: policy.name,
                            scanVulnerabilityId: sv.id,
                            cveId: sv.vulnerability.cveId,
                            severity: sv.vulnerability.severity,
                            action: rule.action,
                            detectedAt: new Date(),
                        });
                    }
                }
            }
        }

        this.logger.log(`Found ${violations.length} policy violations in scan ${scanResultId}`);
        return violations;
    }

    /**
     * Get violation history for an organization
     */
    async getViolationHistory(
        organizationId: string,
        days = 30,
    ): Promise<{
        total: number;
        byPolicy: { policyName: string; count: number }[];
        bySeverity: Record<string, number>;
        trend: { date: string; count: number }[];
    }> {
        // This would query from a violations table in production
        // For now, return mock data structure
        return {
            total: 0,
            byPolicy: [],
            bySeverity: {},
            trend: [],
        };
    }

    /**
     * Export compliance report to various formats
     */
    async exportReport(
        report: ComplianceReport,
        format: 'JSON' | 'PDF' | 'CSV',
    ): Promise<{ data: string; mimeType: string }> {
        switch (format) {
            case 'JSON':
                return {
                    data: JSON.stringify(report, null, 2),
                    mimeType: 'application/json',
                };
            case 'CSV':
                const csv = this.convertToCSV(report);
                return { data: csv, mimeType: 'text/csv' };
            case 'PDF':
                // Would use a PDF library in production
                return {
                    data: JSON.stringify(report),
                    mimeType: 'application/pdf',
                };
            default:
                return { data: JSON.stringify(report), mimeType: 'application/json' };
        }
    }

    // Helper methods

    private calculateComplianceScore(critical: number, high: number, total: number): number {
        if (total === 0) return 100;
        const penalty = (critical * 20) + (high * 10);
        return Math.max(0, Math.min(100, 100 - penalty));
    }

    private generateComplianceSections(
        reportType: string,
        critical: number,
        high: number,
        projectCount: number,
    ): ComplianceSection[] {
        const sections: ComplianceSection[] = [];

        sections.push({
            title: 'Vulnerability Management',
            status: critical === 0 ? (high === 0 ? 'PASS' : 'WARNING') : 'FAIL',
            findings: [
                `${critical} critical vulnerabilities remain unresolved`,
                `${high} high-severity vulnerabilities require attention`,
            ],
            recommendations: critical > 0
                ? ['Immediately address all critical vulnerabilities']
                : ['Continue regular scanning and patching'],
        });

        sections.push({
            title: 'Security Scanning Coverage',
            status: projectCount > 0 ? 'PASS' : 'FAIL',
            findings: [`${projectCount} projects configured for security scanning`],
            recommendations: projectCount === 0
                ? ['Configure at least one project for security scanning']
                : [],
        });

        return sections;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private isViolation(rule: any, vulnerability: any): boolean {
        if (rule.type === 'SEVERITY_THRESHOLD') {
            const severityOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
            const ruleIndex = severityOrder.indexOf(rule.value);
            const vulnIndex = severityOrder.indexOf(vulnerability.severity);
            return vulnIndex >= ruleIndex && rule.action === 'BLOCK';
        }
        return false;
    }

    private convertToCSV(report: ComplianceReport): string {
        const lines = [
            'Section,Status,Findings,Recommendations',
            ...report.sections.map(s =>
                `"${s.title}","${s.status}","${s.findings.join('; ')}","${s.recommendations.join('; ')}"`,
            ),
        ];
        return lines.join('\n');
    }
}
