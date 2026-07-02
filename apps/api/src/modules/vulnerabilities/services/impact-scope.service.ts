import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

export interface ImpactedEntity {
    type: 'project' | 'image' | 'service';
    id: string;
    name: string;
    severity: string;
    occurrences: number;
    lastSeen: Date;
}

export interface CveImpactScope {
    cveId: string;
    title: string;
    severity: string;
    impactedProjects: ImpactedEntity[];
    impactedImages: ImpactedEntity[];
    impactedServices: ImpactedEntity[];
    totalImpactScore: number;
    metrics: {
        projectCount: number;
        imageCount: number;
        totalOccurrences: number;
        oldestOccurrence: Date;
        newestOccurrence: Date;
    };
}

@Injectable()
export class ImpactScopeService {
    private readonly logger = new Logger(ImpactScopeService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Calculate impact scope for a specific CVE
     */
    async calculateCveImpact(cveId: string): Promise<CveImpactScope> {
        const vulnerability = await this.prisma.vulnerability.findUnique({
            where: { cveId },
            include: {
                scanResults: {
                    include: {
                        scanResult: {
                            include: {
                                project: {
                                    include: { organization: true },
                                },
                            },
                        },
                    },
                },
            },
        });

        if (!vulnerability) {
            throw new Error(`CVE ${cveId} not found`);
        }

        // Group by project
        const projectMap = new Map<string, {
            id: string;
            name: string;
            orgName: string;
            occurrences: number;
            lastSeen: Date;
        }>();

        // Group by image
        const imageMap = new Map<string, {
            ref: string;
            occurrences: number;
            lastSeen: Date;
        }>();

        let oldestOccurrence: Date | null = null;
        let newestOccurrence: Date | null = null;

        for (const scanVuln of vulnerability.scanResults) {
            const scan = scanVuln.scanResult;
            const project = scan.project;

            // Track project impact
            const projectData = projectMap.get(project.id) || {
                id: project.id,
                name: project.name,
                orgName: project.organization?.name || 'Unknown',
                occurrences: 0,
                lastSeen: scan.createdAt,
            };
            projectData.occurrences++;
            if (scan.createdAt > projectData.lastSeen) {
                projectData.lastSeen = scan.createdAt;
            }
            projectMap.set(project.id, projectData);

            // Track image impact
            const imageRef = scan.imageRef;
            const imageData = imageMap.get(imageRef) || {
                ref: imageRef,
                occurrences: 0,
                lastSeen: scan.createdAt,
            };
            imageData.occurrences++;
            if (scan.createdAt > imageData.lastSeen) {
                imageData.lastSeen = scan.createdAt;
            }
            imageMap.set(imageRef, imageData);

            // Track temporal bounds
            if (!oldestOccurrence || scan.createdAt < oldestOccurrence) {
                oldestOccurrence = scan.createdAt;
            }
            if (!newestOccurrence || scan.createdAt > newestOccurrence) {
                newestOccurrence = scan.createdAt;
            }
        }

        const impactedProjects: ImpactedEntity[] = Array.from(projectMap.values()).map(p => ({
            type: 'project' as const,
            id: p.id,
            name: `${p.orgName}/${p.name}`,
            severity: vulnerability.severity,
            occurrences: p.occurrences,
            lastSeen: p.lastSeen,
        }));

        const impactedImages: ImpactedEntity[] = Array.from(imageMap.values()).map(i => ({
            type: 'image' as const,
            id: i.ref,
            name: i.ref,
            severity: vulnerability.severity,
            occurrences: i.occurrences,
            lastSeen: i.lastSeen,
        }));

        // Calculate impact score
        const totalImpactScore = this.calculateImpactScore(
            vulnerability.severity,
            projectMap.size,
            imageMap.size,
            vulnerability.scanResults.length,
        );

        return {
            cveId,
            title: vulnerability.title || cveId,
            severity: vulnerability.severity,
            impactedProjects,
            impactedImages,
            impactedServices: [], // Services require additional mapping
            totalImpactScore,
            metrics: {
                projectCount: projectMap.size,
                imageCount: imageMap.size,
                totalOccurrences: vulnerability.scanResults.length,
                oldestOccurrence: oldestOccurrence || new Date(),
                newestOccurrence: newestOccurrence || new Date(),
            },
        };
    }

    /**
     * Calculate impact scope for all CVEs in a project
     */
    async calculateProjectImpact(projectId: string): Promise<{
        projectId: string;
        cveImpacts: CveImpactScope[];
        summary: {
            totalCves: number;
            criticalImpactCves: number;
            highImpactCves: number;
            averageImpactScore: number;
        };
    }> {
        const scanResults = await this.prisma.scanResult.findMany({
            where: { projectId },
            include: {
                vulnerabilities: {
                    include: { vulnerability: true },
                },
            },
        });

        const cveIds = new Set<string>();
        for (const scan of scanResults) {
            for (const vuln of scan.vulnerabilities) {
                cveIds.add(vuln.vulnerability.cveId);
            }
        }

        const cveImpacts: CveImpactScope[] = [];
        let criticalCount = 0;
        let highCount = 0;
        let totalScore = 0;

        for (const cveId of cveIds) {
            const impact = await this.calculateCveImpact(cveId);
            cveImpacts.push(impact);
            totalScore += impact.totalImpactScore;

            if (impact.totalImpactScore >= 9) criticalCount++;
            else if (impact.totalImpactScore >= 7) highCount++;
        }

        return {
            projectId,
            cveImpacts: cveImpacts.sort((a, b) => b.totalImpactScore - a.totalImpactScore),
            summary: {
                totalCves: cveIds.size,
                criticalImpactCves: criticalCount,
                highImpactCves: highCount,
                averageImpactScore: cveIds.size > 0 ? totalScore / cveIds.size : 0,
            },
        };
    }

    /**
     * Get organization-wide impact analysis
     */
    async calculateOrganizationImpact(organizationId: string): Promise<{
        organizationId: string;
        topImpactCves: CveImpactScope[];
        projectImpactSummary: {
            projectId: string;
            projectName: string;
            totalCves: number;
            averageImpactScore: number;
        }[];
    }> {
        const projects = await this.prisma.project.findMany({
            where: { organizationId },
        });

        const projectSummaries: {
            projectId: string;
            projectName: string;
            totalCves: number;
            averageImpactScore: number;
        }[] = [];

        const allCveImpacts = new Map<string, CveImpactScope>();

        for (const project of projects) {
            const impact = await this.calculateProjectImpact(project.id);

            projectSummaries.push({
                projectId: project.id,
                projectName: project.name,
                totalCves: impact.summary.totalCves,
                averageImpactScore: impact.summary.averageImpactScore,
            });

            // Collect all CVE impacts
            for (const cveImpact of impact.cveImpacts) {
                const existing = allCveImpacts.get(cveImpact.cveId);
                if (!existing || cveImpact.totalImpactScore > existing.totalImpactScore) {
                    allCveImpacts.set(cveImpact.cveId, cveImpact);
                }
            }
        }

        // Get top 10 highest impact CVEs
        const topImpactCves = Array.from(allCveImpacts.values())
            .sort((a, b) => b.totalImpactScore - a.totalImpactScore)
            .slice(0, 10);

        return {
            organizationId,
            topImpactCves,
            projectImpactSummary: projectSummaries.sort(
                (a, b) => b.averageImpactScore - a.averageImpactScore,
            ),
        };
    }

    /**
     * Store impact calculation result
     * Note: Requires Prisma client regeneration after migration
     */
    async storeImpactCalculation(cveId: string): Promise<void> {
        const impact = await this.calculateCveImpact(cveId);

        const vulnerability = await this.prisma.vulnerability.findUnique({
            where: { cveId },
        });

        if (!vulnerability) return;

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await (this.prisma as any).vulnerabilityImpact.upsert({
            where: { vulnerabilityId: vulnerability.id },
            create: {
                vulnerabilityId: vulnerability.id,
                affectedProjects: impact.impactedProjects.map(p => p.id),
                affectedImages: impact.impactedImages.map(i => i.id),
                affectedServices: [],
                impactScore: impact.totalImpactScore,
            },
            update: {
                affectedProjects: impact.impactedProjects.map(p => p.id),
                affectedImages: impact.impactedImages.map(i => i.id),
                affectedServices: [],
                impactScore: impact.totalImpactScore,
                calculatedAt: new Date(),
            },
        });
    }

    // Helper methods

    private calculateImpactScore(
        severity: string,
        projectCount: number,
        imageCount: number,
        occurrences: number,
    ): number {
        // Base score from severity
        const severityScores: Record<string, number> = {
            CRITICAL: 10,
            HIGH: 8,
            MEDIUM: 5,
            LOW: 2,
            UNKNOWN: 1,
        };

        const baseScore = severityScores[severity] || 1;

        // Spread factor (how widely it's spread)
        const spreadFactor = Math.log10(projectCount + 1) + Math.log10(imageCount + 1);

        // Occurrence factor (diminishing returns)
        const occurrenceFactor = Math.log10(occurrences + 1);

        // Combined score (normalized to 0-10)
        const rawScore = baseScore * (1 + spreadFactor * 0.2 + occurrenceFactor * 0.1);
        return Math.min(10, rawScore);
    }
}
