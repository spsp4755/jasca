import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface ZeroDayCheckResult {
    cveId: string;
    isZeroDay: boolean;
    isRecent: boolean;
    exploitAvailable: boolean;
    daysSincePublished: number;
    riskFactor: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

@Injectable()
export class ZeroDayService {
    private readonly logger = new Logger(ZeroDayService.name);

    // Zero-day threshold: CVEs published within this many days with no patch
    private readonly ZERO_DAY_THRESHOLD_DAYS = 7;

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Check if a vulnerability is a zero-day
     */
    async checkZeroDay(cveId: string): Promise<ZeroDayCheckResult> {
        const vulnerability = await this.prisma.vulnerability.findUnique({
            where: { cveId },
        });

        if (!vulnerability) {
            return {
                cveId,
                isZeroDay: false,
                isRecent: false,
                exploitAvailable: false,
                daysSincePublished: -1,
                riskFactor: 'LOW',
            };
        }

        const now = new Date();
        const publishedAt = vulnerability.publishedAt;
        const daysSincePublished = publishedAt
            ? Math.floor((now.getTime() - publishedAt.getTime()) / (1000 * 60 * 60 * 24))
            : -1;

        const isRecent = daysSincePublished >= 0 && daysSincePublished <= this.ZERO_DAY_THRESHOLD_DAYS;
        const exploitAvailable = vulnerability.exploitAvailable || false;

        // Zero-day: recently published with exploit, or flagged as zero-day
        const isZeroDay = vulnerability.isZeroDay || (isRecent && exploitAvailable);

        const riskFactor = this.calculateRiskFactor(
            isZeroDay,
            exploitAvailable,
            vulnerability.severity,
            daysSincePublished,
        );

        return {
            cveId,
            isZeroDay,
            isRecent,
            exploitAvailable,
            daysSincePublished,
            riskFactor,
        };
    }

    /**
     * Flag a CVE as zero-day
     */
    async flagZeroDay(cveId: string): Promise<void> {
        await this.prisma.vulnerability.update({
            where: { cveId },
            data: {
                isZeroDay: true,
                zeroDetectedAt: new Date(),
            },
        });

        this.logger.warn(`Flagged ${cveId} as zero-day vulnerability`);
    }

    /**
     * Unflag a CVE as zero-day
     */
    async unflagZeroDay(cveId: string): Promise<void> {
        await this.prisma.vulnerability.update({
            where: { cveId },
            data: {
                isZeroDay: false,
                zeroDetectedAt: null,
            },
        });
    }

    /**
     * Get all zero-day vulnerabilities
     */
    async getAllZeroDays(): Promise<{
        cveId: string;
        title: string;
        severity: string;
        detectedAt: Date;
        exploitAvailable: boolean;
    }[]> {
        const zeroDays = await this.prisma.vulnerability.findMany({
            where: { isZeroDay: true },
            orderBy: { zeroDetectedAt: 'desc' },
        });

        return zeroDays.map(v => ({
            cveId: v.cveId,
            title: v.title || v.cveId,
            severity: v.severity,
            detectedAt: v.zeroDetectedAt || v.createdAt,
            exploitAvailable: v.exploitAvailable || false,
        }));
    }

    /**
     * Scan for potential zero-days in scan results
     */
    async scanForZeroDays(scanResultId: string): Promise<ZeroDayCheckResult[]> {
        const scanVulns = await this.prisma.scanVulnerability.findMany({
            where: { scanResultId },
            include: { vulnerability: true },
        });

        const results: ZeroDayCheckResult[] = [];

        for (const scanVuln of scanVulns) {
            const result = await this.checkZeroDay(scanVuln.vulnerability.cveId);

            if (result.isZeroDay || result.isRecent) {
                results.push(result);
            }
        }

        return results;
    }

    /**
     * Get zero-day statistics for an organization
     */
    async getZeroDayStats(organizationId: string): Promise<{
        totalZeroDays: number;
        activeZeroDays: number;
        recentZeroDays: number;
        byProject: { projectId: string; projectName: string; count: number }[];
    }> {
        const projects = await this.prisma.project.findMany({
            where: { organizationId },
            include: {
                scanResults: {
                    include: {
                        vulnerabilities: {
                            include: { vulnerability: true },
                        },
                    },
                    orderBy: { createdAt: 'desc' },
                    take: 1, // Latest scan only
                },
            },
        });

        let totalZeroDays = 0;
        const byProject: { projectId: string; projectName: string; count: number }[] = [];
        const seenCves = new Set<string>();

        for (const project of projects) {
            let projectCount = 0;

            for (const scan of project.scanResults) {
                for (const scanVuln of scan.vulnerabilities) {
                    if (scanVuln.vulnerability.isZeroDay) {
                        projectCount++;
                        if (!seenCves.has(scanVuln.vulnerability.cveId)) {
                            seenCves.add(scanVuln.vulnerability.cveId);
                            totalZeroDays++;
                        }
                    }
                }
            }

            if (projectCount > 0) {
                byProject.push({
                    projectId: project.id,
                    projectName: project.name,
                    count: projectCount,
                });
            }
        }

        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

        const recentZeroDays = await this.prisma.vulnerability.count({
            where: {
                isZeroDay: true,
                zeroDetectedAt: { gte: oneWeekAgo },
            },
        });

        return {
            totalZeroDays,
            activeZeroDays: seenCves.size,
            recentZeroDays,
            byProject: byProject.sort((a, b) => b.count - a.count),
        };
    }

    // Helper methods

    private calculateRiskFactor(
        isZeroDay: boolean,
        exploitAvailable: boolean,
        severity: string,
        daysSincePublished: number,
    ): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
        if (isZeroDay && exploitAvailable && (severity === 'CRITICAL' || severity === 'HIGH')) {
            return 'CRITICAL';
        }
        if (isZeroDay || (exploitAvailable && severity === 'CRITICAL')) {
            return 'HIGH';
        }
        if (exploitAvailable || daysSincePublished <= 30) {
            return 'MEDIUM';
        }
        return 'LOW';
    }
}
