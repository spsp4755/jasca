import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * External threat intelligence feed entry
 */
export interface ThreatIntelEntry {
    cveId: string;
    source: string;
    threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    exploitAvailable: boolean;
    exploitMaturity: 'POC' | 'WEAPONIZED' | 'IN_THE_WILD' | 'UNKNOWN';
    activelyExploited: boolean;
    lastUpdated: Date;
    references: string[];
}

/**
 * Mock threat intelligence database
 * In production, this would connect to external sources like:
 * - CISA KEV (Known Exploited Vulnerabilities)
 * - Exploit-DB
 * - VulnDB
 * - NVD enriched data
 */
const THREAT_INTEL_MOCK: Record<string, ThreatIntelEntry> = {
    'CVE-2021-44228': { // Log4Shell
        cveId: 'CVE-2021-44228',
        source: 'CISA-KEV',
        threatLevel: 'CRITICAL',
        exploitAvailable: true,
        exploitMaturity: 'IN_THE_WILD',
        activelyExploited: true,
        lastUpdated: new Date('2021-12-10'),
        references: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    },
    'CVE-2021-45046': {
        cveId: 'CVE-2021-45046',
        source: 'CISA-KEV',
        threatLevel: 'CRITICAL',
        exploitAvailable: true,
        exploitMaturity: 'IN_THE_WILD',
        activelyExploited: true,
        lastUpdated: new Date('2021-12-14'),
        references: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    },
    'CVE-2023-44487': { // HTTP/2 Rapid Reset
        cveId: 'CVE-2023-44487',
        source: 'CISA-KEV',
        threatLevel: 'HIGH',
        exploitAvailable: true,
        exploitMaturity: 'IN_THE_WILD',
        activelyExploited: true,
        lastUpdated: new Date('2023-10-10'),
        references: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    },
};

@Injectable()
export class ThreatIntelService {
    private readonly logger = new Logger(ThreatIntelService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Get threat intelligence for a CVE
     */
    async getThreatIntel(cveId: string): Promise<ThreatIntelEntry | null> {
        // In production, this would query external APIs
        // For now, use mock data or return null
        const mockData = THREAT_INTEL_MOCK[cveId];

        if (mockData) {
            return mockData;
        }

        // Check if it's in CISA KEV (simulated)
        const isCritical = cveId.includes('2021') || cveId.includes('2022') || cveId.includes('2023');

        if (isCritical) {
            return {
                cveId,
                source: 'SIMULATED',
                threatLevel: 'MEDIUM',
                exploitAvailable: false,
                exploitMaturity: 'UNKNOWN',
                activelyExploited: false,
                lastUpdated: new Date(),
                references: [],
            };
        }

        return null;
    }

    /**
     * Enrich vulnerability with threat intel
     */
    async enrichVulnerability(cveId: string): Promise<{
        cveId: string;
        enriched: boolean;
        threatLevel?: string;
        exploitAvailable?: boolean;
        activelyExploited?: boolean;
    }> {
        const threatIntel = await this.getThreatIntel(cveId);

        if (!threatIntel) {
            return { cveId, enriched: false };
        }

        // Update vulnerability with enriched data
        try {
            await this.prisma.vulnerability.update({
                where: { cveId },
                data: {
                    exploitAvailable: threatIntel.exploitAvailable,
                    isZeroDay: threatIntel.activelyExploited,
                    zeroDetectedAt: threatIntel.activelyExploited ? new Date() : undefined,
                },
            });

            return {
                cveId,
                enriched: true,
                threatLevel: threatIntel.threatLevel,
                exploitAvailable: threatIntel.exploitAvailable,
                activelyExploited: threatIntel.activelyExploited,
            };
        } catch {
            return { cveId, enriched: false };
        }
    }

    /**
     * Batch enrich vulnerabilities from a scan
     */
    async enrichScanVulnerabilities(scanResultId: string): Promise<{
        total: number;
        enriched: number;
        critical: number;
        activelyExploited: number;
    }> {
        const scanVulns = await this.prisma.scanVulnerability.findMany({
            where: { scanResultId },
            include: { vulnerability: true },
        });

        let enriched = 0;
        let critical = 0;
        let activelyExploited = 0;

        for (const scanVuln of scanVulns) {
            const result = await this.enrichVulnerability(scanVuln.vulnerability.cveId);

            if (result.enriched) {
                enriched++;
                if (result.threatLevel === 'CRITICAL') critical++;
                if (result.activelyExploited) activelyExploited++;
            }
        }

        this.logger.log(
            `Enriched ${enriched}/${scanVulns.length} vulnerabilities for scan ${scanResultId}`,
        );

        return {
            total: scanVulns.length,
            enriched,
            critical,
            activelyExploited,
        };
    }

    /**
     * Get CISA KEV matches for an organization
     */
    async getCisaKevMatches(organizationId: string): Promise<{
        matches: { cveId: string; projectName: string; severity: string }[];
        totalMatches: number;
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
                    take: 1,
                },
            },
        });

        const matches: { cveId: string; projectName: string; severity: string }[] = [];
        const cveSet = new Set<string>();

        for (const project of projects) {
            for (const scan of project.scanResults) {
                for (const scanVuln of scan.vulnerabilities) {
                    const cveId = scanVuln.vulnerability.cveId;
                    const threatIntel = await this.getThreatIntel(cveId);

                    if (threatIntel && threatIntel.activelyExploited && !cveSet.has(cveId)) {
                        cveSet.add(cveId);
                        matches.push({
                            cveId,
                            projectName: project.name,
                            severity: scanVuln.vulnerability.severity,
                        });
                    }
                }
            }
        }

        return {
            matches: matches.sort((a, b) => {
                const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
                return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
            }),
            totalMatches: matches.length,
        };
    }

    /**
     * Check if CVE is in CISA KEV catalog
     */
    async isInCisaKev(cveId: string): Promise<boolean> {
        const intel = await this.getThreatIntel(cveId);
        return intel?.activelyExploited || false;
    }
}
