import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

export interface ConditionalPolicyInput {
    scanResultId: string;
    projectId: string;
    environment: 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION' | 'ALL';
}

export interface ConditionalVulnerability {
    id: string;
    cveId: string;
    severity: string;
    isNew: boolean;
    firstSeenAt: Date;
    daysSinceFirstSeen: number;
    action: 'BLOCK' | 'WARN' | 'INFO' | 'ALLOW';
    reason: string;
}

export interface ConditionalPolicyResult {
    totalVulnerabilities: number;
    newVulnerabilities: ConditionalVulnerability[];
    existingVulnerabilities: ConditionalVulnerability[];
    blockedCount: number;
    warnedCount: number;
    allowedCount: number;
    allowed: boolean;
    summary: string;
}

@Injectable()
export class ConditionalPolicyService {
    private readonly logger = new Logger(ConditionalPolicyService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Evaluate vulnerabilities with conditional policy logic
     * - New vulnerabilities: Apply strict policy (BLOCK if Critical/High)
     * - Existing vulnerabilities: Apply lenient policy (WARN instead of BLOCK)
     */
    async evaluateConditionalPolicy(
        input: ConditionalPolicyInput,
    ): Promise<ConditionalPolicyResult> {
        const scanVulnerabilities = await this.prisma.scanVulnerability.findMany({
            where: { scanResultId: input.scanResultId },
            include: {
                vulnerability: true,
                scanResult: true,
            },
        });

        // Get historical scan results for the same project to identify new vs existing
        const historicalScans = await this.prisma.scanResult.findMany({
            where: {
                projectId: input.projectId,
                id: { not: input.scanResultId },
            },
            include: {
                vulnerabilities: {
                    include: { vulnerability: true },
                },
            },
            orderBy: { createdAt: 'asc' },
        });

        // Build a map of when each CVE was first seen
        const cveFirstSeen = new Map<string, Date>();

        for (const scan of historicalScans) {
            for (const vuln of scan.vulnerabilities) {
                const cveId = vuln.vulnerability.cveId;
                if (!cveFirstSeen.has(cveId)) {
                    cveFirstSeen.set(cveId, scan.createdAt);
                }
            }
        }

        const newVulnerabilities: ConditionalVulnerability[] = [];
        const existingVulnerabilities: ConditionalVulnerability[] = [];
        const currentScan = scanVulnerabilities[0]?.scanResult;
        const now = currentScan?.createdAt || new Date();

        let blockedCount = 0;
        let warnedCount = 0;
        let allowedCount = 0;

        for (const scanVuln of scanVulnerabilities) {
            const cveId = scanVuln.vulnerability.cveId;
            const severity = scanVuln.vulnerability.severity;
            const firstSeenAt = cveFirstSeen.get(cveId);
            const isNew = !firstSeenAt;
            const daysSinceFirstSeen = firstSeenAt
                ? Math.floor((now.getTime() - firstSeenAt.getTime()) / (1000 * 60 * 60 * 24))
                : 0;

            // Determine action based on whether it's new or existing
            const { action, reason } = this.determineAction(
                severity,
                isNew,
                daysSinceFirstSeen,
                input.environment,
            );

            const conditionalVuln: ConditionalVulnerability = {
                id: scanVuln.id,
                cveId,
                severity,
                isNew,
                firstSeenAt: firstSeenAt || now,
                daysSinceFirstSeen,
                action,
                reason,
            };

            if (isNew) {
                newVulnerabilities.push(conditionalVuln);
            } else {
                existingVulnerabilities.push(conditionalVuln);
            }

            // Count actions
            switch (action) {
                case 'BLOCK':
                    blockedCount++;
                    break;
                case 'WARN':
                    warnedCount++;
                    break;
                default:
                    allowedCount++;
            }
        }

        const allowed = blockedCount === 0;
        const summary = this.generateSummary(
            newVulnerabilities.length,
            existingVulnerabilities.length,
            blockedCount,
            warnedCount,
            input.environment,
        );

        return {
            totalVulnerabilities: scanVulnerabilities.length,
            newVulnerabilities,
            existingVulnerabilities,
            blockedCount,
            warnedCount,
            allowedCount,
            allowed,
            summary,
        };
    }

    /**
     * Check if a vulnerability is new for a project
     */
    async isNewVulnerability(
        projectId: string,
        cveId: string,
        beforeDate?: Date,
    ): Promise<boolean> {
        const existingVuln = await this.prisma.scanVulnerability.findFirst({
            where: {
                scanResult: {
                    projectId,
                    createdAt: beforeDate ? { lt: beforeDate } : undefined,
                },
                vulnerability: {
                    cveId,
                },
            },
        });

        return !existingVuln;
    }

    /**
     * Get new vulnerability count for a scan
     */
    async getNewVulnerabilityCount(scanResultId: string): Promise<{
        total: number;
        new: number;
        existing: number;
    }> {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: {
                vulnerabilities: {
                    include: { vulnerability: true },
                },
            },
        });

        if (!scan) {
            return { total: 0, new: 0, existing: 0 };
        }

        let newCount = 0;
        let existingCount = 0;

        for (const vuln of scan.vulnerabilities) {
            const isNew = await this.isNewVulnerability(
                scan.projectId,
                vuln.vulnerability.cveId,
                scan.createdAt,
            );

            if (isNew) {
                newCount++;
            } else {
                existingCount++;
            }
        }

        return {
            total: scan.vulnerabilities.length,
            new: newCount,
            existing: existingCount,
        };
    }

    // Helper methods

    private determineAction(
        severity: string,
        isNew: boolean,
        daysSinceFirstSeen: number,
        environment: string,
    ): { action: 'BLOCK' | 'WARN' | 'INFO' | 'ALLOW'; reason: string } {
        // Production is strictest
        if (environment === 'PRODUCTION') {
            if (isNew && (severity === 'CRITICAL' || severity === 'HIGH')) {
                return {
                    action: 'BLOCK',
                    reason: `New ${severity} vulnerability in production`,
                };
            }
            if (!isNew && severity === 'CRITICAL') {
                return {
                    action: 'WARN',
                    reason: `Existing CRITICAL vulnerability (${daysSinceFirstSeen} days old)`,
                };
            }
        }

        // Staging - block new criticals
        if (environment === 'STAGING') {
            if (isNew && severity === 'CRITICAL') {
                return {
                    action: 'BLOCK',
                    reason: 'New CRITICAL vulnerability in staging',
                };
            }
            if (severity === 'CRITICAL' || severity === 'HIGH') {
                return {
                    action: 'WARN',
                    reason: `${severity} vulnerability in staging`,
                };
            }
        }

        // Development - only warn, never block
        if (environment === 'DEVELOPMENT') {
            if (severity === 'CRITICAL' || severity === 'HIGH') {
                return {
                    action: 'WARN',
                    reason: `${severity} vulnerability (development mode - not blocking)`,
                };
            }
            return {
                action: 'INFO',
                reason: `${severity} vulnerability logged for development`,
            };
        }

        // Default (ALL) - moderate policy
        if (isNew && severity === 'CRITICAL') {
            return {
                action: 'BLOCK',
                reason: 'New CRITICAL vulnerability detected',
            };
        }
        if (isNew && severity === 'HIGH') {
            return {
                action: 'WARN',
                reason: 'New HIGH vulnerability detected',
            };
        }
        if (!isNew && (severity === 'CRITICAL' || severity === 'HIGH')) {
            return {
                action: 'WARN',
                reason: `Existing ${severity} vulnerability (first seen ${daysSinceFirstSeen} days ago)`,
            };
        }

        return {
            action: 'ALLOW',
            reason: `${severity} vulnerability - allowed by policy`,
        };
    }

    private generateSummary(
        newCount: number,
        existingCount: number,
        blockedCount: number,
        warnedCount: number,
        environment: string,
    ): string {
        const status = blockedCount > 0 ? 'BLOCKED' : 'ALLOWED';
        return `[${environment}] ${status}: ${newCount} new, ${existingCount} existing vulnerabilities. ` +
            `${blockedCount} blocked, ${warnedCount} warnings.`;
    }
}
