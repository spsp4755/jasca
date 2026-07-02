import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * MITRE ATT&CK Technique mapping for vulnerability analysis
 */
interface MitreTechnique {
    id: string;
    name: string;
    tacticId: string;
    tacticName: string;
    description?: string;
}

/**
 * Mapping result for a vulnerability
 */
export interface MitreMappingResult {
    cveId: string;
    techniques: MitreTechnique[];
    confidence: number;
}

// Common CWE to MITRE ATT&CK mappings
const CWE_TO_MITRE: Record<string, MitreTechnique[]> = {
    'CWE-78': [ // OS Command Injection
        { id: 'T1059', name: 'Command and Scripting Interpreter', tacticId: 'TA0002', tacticName: 'Execution' },
    ],
    'CWE-79': [ // XSS
        { id: 'T1189', name: 'Drive-by Compromise', tacticId: 'TA0001', tacticName: 'Initial Access' },
        { id: 'T1059.007', name: 'JavaScript', tacticId: 'TA0002', tacticName: 'Execution' },
    ],
    'CWE-89': [ // SQL Injection
        { id: 'T1190', name: 'Exploit Public-Facing Application', tacticId: 'TA0001', tacticName: 'Initial Access' },
    ],
    'CWE-94': [ // Code Injection
        { id: 'T1059', name: 'Command and Scripting Interpreter', tacticId: 'TA0002', tacticName: 'Execution' },
    ],
    'CWE-119': [ // Buffer Overflow
        { id: 'T1203', name: 'Exploitation for Client Execution', tacticId: 'TA0002', tacticName: 'Execution' },
    ],
    'CWE-190': [ // Integer Overflow
        { id: 'T1203', name: 'Exploitation for Client Execution', tacticId: 'TA0002', tacticName: 'Execution' },
    ],
    'CWE-200': [ // Information Exposure
        { id: 'T1005', name: 'Data from Local System', tacticId: 'TA0009', tacticName: 'Collection' },
    ],
    'CWE-287': [ // Improper Authentication
        { id: 'T1078', name: 'Valid Accounts', tacticId: 'TA0001', tacticName: 'Initial Access' },
    ],
    'CWE-306': [ // Missing Authentication
        { id: 'T1078', name: 'Valid Accounts', tacticId: 'TA0001', tacticName: 'Initial Access' },
    ],
    'CWE-352': [ // CSRF
        { id: 'T1185', name: 'Browser Session Hijacking', tacticId: 'TA0009', tacticName: 'Collection' },
    ],
    'CWE-434': [ // Unrestricted Upload
        { id: 'T1105', name: 'Ingress Tool Transfer', tacticId: 'TA0011', tacticName: 'Command and Control' },
    ],
    'CWE-502': [ // Deserialization
        { id: 'T1059', name: 'Command and Scripting Interpreter', tacticId: 'TA0002', tacticName: 'Execution' },
    ],
    'CWE-611': [ // XXE
        { id: 'T1190', name: 'Exploit Public-Facing Application', tacticId: 'TA0001', tacticName: 'Initial Access' },
    ],
    'CWE-918': [ // SSRF
        { id: 'T1090', name: 'Proxy', tacticId: 'TA0011', tacticName: 'Command and Control' },
    ],
};

@Injectable()
export class MitreAttackService {
    private readonly logger = new Logger(MitreAttackService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Map a vulnerability to MITRE ATT&CK techniques based on CWE IDs
     */
    async mapVulnerabilityToMitre(
        vulnerabilityId: string,
    ): Promise<MitreMappingResult> {
        const vulnerability = await this.prisma.vulnerability.findUnique({
            where: { id: vulnerabilityId },
        });

        if (!vulnerability) {
            return { cveId: '', techniques: [], confidence: 0 };
        }

        const techniques: MitreTechnique[] = [];
        const cweIds = vulnerability.cweIds || [];

        for (const cweId of cweIds) {
            const normalizedCwe = cweId.toUpperCase().replace(/[^A-Z0-9-]/g, '');
            const mappedTechniques = CWE_TO_MITRE[normalizedCwe] || [];

            for (const technique of mappedTechniques) {
                if (!techniques.some(t => t.id === technique.id)) {
                    techniques.push(technique);
                }
            }
        }

        const confidence = techniques.length > 0 ? 0.7 : 0;

        return {
            cveId: vulnerability.cveId,
            techniques,
            confidence,
        };
    }

    /**
     * Store MITRE mapping for a vulnerability
     */
    async storeMitreMapping(
        vulnerabilityId: string,
        techniques: MitreTechnique[],
        confidence: number,
    ): Promise<void> {
        for (const technique of techniques) {
            await this.prisma.mitreMapping.upsert({
                where: {
                    vulnerabilityId_techniqueId: {
                        vulnerabilityId,
                        techniqueId: technique.id,
                    },
                },
                create: {
                    vulnerabilityId,
                    techniqueId: technique.id,
                    techniqueName: technique.name,
                    tacticId: technique.tacticId,
                    tacticName: technique.tacticName,
                    confidence,
                },
                update: {
                    confidence,
                },
            });
        }
    }

    /**
     * Get MITRE mappings for a vulnerability
     */
    async getMitreMappings(vulnerabilityId: string) {
        return this.prisma.mitreMapping.findMany({
            where: { vulnerabilityId },
        });
    }

    /**
     * Get all vulnerabilities by MITRE technique
     */
    async getVulnerabilitiesByTechnique(techniqueId: string) {
        const mappings = await this.prisma.mitreMapping.findMany({
            where: { techniqueId },
            include: { vulnerability: true },
        });

        return mappings.map(m => m.vulnerability);
    }

    /**
     * Get MITRE coverage summary for a project
     */
    async getMitreCoverage(projectId: string): Promise<{
        tactics: { id: string; name: string; count: number }[];
        techniques: { id: string; name: string; count: number }[];
        totalMappedVulns: number;
    }> {
        const scans = await this.prisma.scanResult.findMany({
            where: { projectId },
            include: {
                vulnerabilities: {
                    include: {
                        vulnerability: {
                            include: { mitreMapping: true },
                        },
                    },
                },
            },
        });

        const tacticsMap = new Map<string, { name: string; count: number }>();
        const techniquesMap = new Map<string, { name: string; count: number }>();
        let totalMapped = 0;

        for (const scan of scans) {
            for (const scanVuln of scan.vulnerabilities) {
                const mappings = scanVuln.vulnerability.mitreMapping || [];
                if (mappings.length > 0) {
                    totalMapped++;
                }

                for (const mapping of mappings) {
                    const tacticData = tacticsMap.get(mapping.tacticId) || {
                        name: mapping.tacticName,
                        count: 0,
                    };
                    tacticData.count++;
                    tacticsMap.set(mapping.tacticId, tacticData);

                    const techData = techniquesMap.get(mapping.techniqueId) || {
                        name: mapping.techniqueName,
                        count: 0,
                    };
                    techData.count++;
                    techniquesMap.set(mapping.techniqueId, techData);
                }
            }
        }

        return {
            tactics: Array.from(tacticsMap.entries()).map(([id, data]) => ({
                id,
                name: data.name,
                count: data.count,
            })),
            techniques: Array.from(techniquesMap.entries()).map(([id, data]) => ({
                id,
                name: data.name,
                count: data.count,
            })),
            totalMappedVulns: totalMapped,
        };
    }
}
