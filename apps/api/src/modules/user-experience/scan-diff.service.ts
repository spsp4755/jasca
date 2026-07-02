import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface VulnDiffEntry {
    cveId: string;
    title: string;
    severity: string;
    status: 'NEW' | 'FIXED' | 'CHANGED' | 'UNCHANGED';
    oldSeverity?: string;
    newSeverity?: string;
}

export interface ScanDiffResult {
    baseScanId: string;
    compareScanId: string;
    baseScanDate: Date;
    compareScanDate: Date;
    summary: {
        new: number;
        fixed: number;
        changed: number;
        unchanged: number;
    };
    newVulnerabilities: VulnDiffEntry[];
    fixedVulnerabilities: VulnDiffEntry[];
    changedVulnerabilities: VulnDiffEntry[];
}

@Injectable()
export class ScanDiffService {
    private readonly logger = new Logger(ScanDiffService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Compare two scan results and show differences
     */
    async compareScanResults(
        baseScanId: string,
        compareScanId: string,
    ): Promise<ScanDiffResult> {
        const [baseScan, compareScan] = await Promise.all([
            this.prisma.scanResult.findUnique({
                where: { id: baseScanId },
                include: {
                    vulnerabilities: {
                        include: { vulnerability: true },
                    },
                },
            }),
            this.prisma.scanResult.findUnique({
                where: { id: compareScanId },
                include: {
                    vulnerabilities: {
                        include: { vulnerability: true },
                    },
                },
            }),
        ]);

        if (!baseScan || !compareScan) {
            throw new Error('One or both scans not found');
        }

        // Build maps for comparison
        const baseVulns = new Map<string, { severity: string; vuln: typeof baseScan.vulnerabilities[0] }>();
        const compareVulns = new Map<string, { severity: string; vuln: typeof compareScan.vulnerabilities[0] }>();

        for (const sv of baseScan.vulnerabilities) {
            baseVulns.set(sv.vulnerability.cveId, {
                severity: sv.vulnerability.severity,
                vuln: sv,
            });
        }

        for (const sv of compareScan.vulnerabilities) {
            compareVulns.set(sv.vulnerability.cveId, {
                severity: sv.vulnerability.severity,
                vuln: sv,
            });
        }

        const newVulnerabilities: VulnDiffEntry[] = [];
        const fixedVulnerabilities: VulnDiffEntry[] = [];
        const changedVulnerabilities: VulnDiffEntry[] = [];
        let unchangedCount = 0;

        // Find new vulnerabilities (in compare but not in base)
        for (const [cveId, compareData] of compareVulns) {
            if (!baseVulns.has(cveId)) {
                newVulnerabilities.push({
                    cveId,
                    title: compareData.vuln.vulnerability.title || cveId,
                    severity: compareData.severity,
                    status: 'NEW',
                });
            } else {
                const baseData = baseVulns.get(cveId)!;
                if (baseData.severity !== compareData.severity) {
                    changedVulnerabilities.push({
                        cveId,
                        title: compareData.vuln.vulnerability.title || cveId,
                        severity: compareData.severity,
                        status: 'CHANGED',
                        oldSeverity: baseData.severity,
                        newSeverity: compareData.severity,
                    });
                } else {
                    unchangedCount++;
                }
            }
        }

        // Find fixed vulnerabilities (in base but not in compare)
        for (const [cveId, baseData] of baseVulns) {
            if (!compareVulns.has(cveId)) {
                fixedVulnerabilities.push({
                    cveId,
                    title: baseData.vuln.vulnerability.title || cveId,
                    severity: baseData.severity,
                    status: 'FIXED',
                });
            }
        }

        // Sort by severity
        const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
        const sortBySeverity = (a: VulnDiffEntry, b: VulnDiffEntry) =>
            severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);

        newVulnerabilities.sort(sortBySeverity);
        fixedVulnerabilities.sort(sortBySeverity);
        changedVulnerabilities.sort(sortBySeverity);

        return {
            baseScanId,
            compareScanId,
            baseScanDate: baseScan.createdAt,
            compareScanDate: compareScan.createdAt,
            summary: {
                new: newVulnerabilities.length,
                fixed: fixedVulnerabilities.length,
                changed: changedVulnerabilities.length,
                unchanged: unchangedCount,
            },
            newVulnerabilities,
            fixedVulnerabilities,
            changedVulnerabilities,
        };
    }

    /**
     * Get diff between latest two scans of a project
     */
    async getLatestDiff(projectId: string): Promise<ScanDiffResult | null> {
        const scans = await this.prisma.scanResult.findMany({
            where: { projectId },
            orderBy: { createdAt: 'desc' },
            take: 2,
        });

        if (scans.length < 2) {
            return null;
        }

        return this.compareScanResults(scans[1].id, scans[0].id);
    }

    /**
     * Get vulnerability trend over scans
     */
    async getVulnerabilityTrend(
        projectId: string,
        limit = 10,
    ): Promise<{
        scans: { id: string; date: Date; critical: number; high: number; medium: number; low: number }[];
    }> {
        const scans = await this.prisma.scanResult.findMany({
            where: { projectId },
            orderBy: { createdAt: 'asc' },
            take: limit,
            include: {
                vulnerabilities: {
                    include: { vulnerability: true },
                },
            },
        });

        return {
            scans: scans.map(scan => {
                const counts = { critical: 0, high: 0, medium: 0, low: 0 };
                for (const sv of scan.vulnerabilities) {
                    const sev = sv.vulnerability.severity.toLowerCase();
                    if (sev === 'critical') counts.critical++;
                    else if (sev === 'high') counts.high++;
                    else if (sev === 'medium') counts.medium++;
                    else counts.low++;
                }
                return {
                    id: scan.id,
                    date: scan.createdAt,
                    ...counts,
                };
            }),
        };
    }
}
