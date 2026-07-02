import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface GlobalDashboardStats {
    organizations: {
        id: string;
        name: string;
        totalProjects: number;
        totalScans: number;
        totalVulnerabilities: number;
        criticalCount: number;
        highCount: number;
    }[];
    totals: {
        organizations: number;
        projects: number;
        scans: number;
        vulnerabilities: number;
        critical: number;
        high: number;
    };
}

@Injectable()
export class MultiOrgService {
    private readonly logger = new Logger(MultiOrgService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Get global dashboard statistics across all organizations
     */
    async getGlobalDashboard(): Promise<GlobalDashboardStats> {
        const organizations = await this.prisma.organization.findMany({
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

        const orgStats = organizations.map(org => {
            let totalVulns = 0;
            let criticalCount = 0;
            let highCount = 0;
            let totalScans = 0;

            for (const project of org.projects) {
                totalScans += project.scanResults.length;
                for (const scan of project.scanResults) {
                    for (const sv of scan.vulnerabilities) {
                        totalVulns++;
                        if (sv.vulnerability.severity === 'CRITICAL') criticalCount++;
                        else if (sv.vulnerability.severity === 'HIGH') highCount++;
                    }
                }
            }

            return {
                id: org.id,
                name: org.name,
                totalProjects: org.projects.length,
                totalScans,
                totalVulnerabilities: totalVulns,
                criticalCount,
                highCount,
            };
        });

        return {
            organizations: orgStats,
            totals: {
                organizations: organizations.length,
                projects: orgStats.reduce((sum, o) => sum + o.totalProjects, 0),
                scans: orgStats.reduce((sum, o) => sum + o.totalScans, 0),
                vulnerabilities: orgStats.reduce((sum, o) => sum + o.totalVulnerabilities, 0),
                critical: orgStats.reduce((sum, o) => sum + o.criticalCount, 0),
                high: orgStats.reduce((sum, o) => sum + o.highCount, 0),
            },
        };
    }

    /**
     * Get inherited policies for a project
     */
    async getInheritedPolicies(projectId: string) {
        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            include: { organization: true },
        });

        if (!project) return [];

        // Get organization-level policies (inherited)
        const orgPolicies = await this.prisma.policy.findMany({
            where: {
                organizationId: project.organizationId,
                projectId: null,
                isActive: true,
            },
            include: { rules: true },
        });

        // Get project-specific policies
        const projectPolicies = await this.prisma.policy.findMany({
            where: {
                projectId,
                isActive: true,
            },
            include: { rules: true },
        });

        return {
            inherited: orgPolicies.map(p => ({ ...p, source: 'ORGANIZATION' })),
            project: projectPolicies.map(p => ({ ...p, source: 'PROJECT' })),
            combined: [...orgPolicies, ...projectPolicies],
        };
    }

    /**
     * Get cross-organization vulnerability statistics
     */
    async getCrossOrgVulnStats(): Promise<{
        topCves: { cveId: string; title: string; severity: string; orgCount: number }[];
        severityDistribution: Record<string, number>;
    }> {
        const vulns = await this.prisma.scanVulnerability.findMany({
            include: {
                vulnerability: true,
                scanResult: {
                    include: {
                        project: { select: { organizationId: true } },
                    },
                },
            },
        });

        const cveOrgMap = new Map<string, Set<string>>();
        const cveDetails = new Map<string, { title: string; severity: string }>();
        const severityCounts: Record<string, number> = {};

        for (const sv of vulns) {
            const cveId = sv.vulnerability.cveId;
            const orgId = sv.scanResult.project.organizationId;
            const severity = sv.vulnerability.severity;

            if (!cveOrgMap.has(cveId)) {
                cveOrgMap.set(cveId, new Set());
                cveDetails.set(cveId, {
                    title: sv.vulnerability.title || cveId,
                    severity,
                });
            }
            cveOrgMap.get(cveId)!.add(orgId);

            severityCounts[severity] = (severityCounts[severity] || 0) + 1;
        }

        const topCves = Array.from(cveOrgMap.entries())
            .map(([cveId, orgs]) => ({
                cveId,
                title: cveDetails.get(cveId)!.title,
                severity: cveDetails.get(cveId)!.severity,
                orgCount: orgs.size,
            }))
            .filter(c => c.orgCount > 1)
            .sort((a, b) => b.orgCount - a.orgCount)
            .slice(0, 20);

        return {
            topCves,
            severityDistribution: severityCounts,
        };
    }
}
