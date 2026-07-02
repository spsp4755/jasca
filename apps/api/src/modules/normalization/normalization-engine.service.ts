import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import {
    NormalizedVulnerability,
    NormalizedScanResult,
    PackageEcosystem,
    ArtifactType,
    CURRENT_SCHEMA_VERSION,
    TRIVY_SCHEMA_MAPPINGS,
} from './schemas/normalized-vulnerability.schema';
import { NormalizationFormat } from './dto/normalize.dto';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';


@Injectable()
export class NormalizationEngineService {
    private readonly logger = new Logger(NormalizationEngineService.name);

    /**
     * Normalize scan result from any supported format to internal schema
     */
    normalize(
        rawResult: any,
        sourceFormat: NormalizationFormat,
        options?: { schemaVersion?: string; scannerVersion?: string },
    ): NormalizedScanResult {
        this.logger.debug(`Normalizing result from format: ${sourceFormat}`);

        switch (sourceFormat) {
            case NormalizationFormat.TRIVY_JSON:
                return this.normalizeTrivyJson(rawResult, options);
            case NormalizationFormat.TRIVY_SARIF:
                return this.normalizeTrivySarif(rawResult, options);
            case NormalizationFormat.GRYPE_JSON:
                return this.normalizeGrypeJson(rawResult, options);
            case NormalizationFormat.SNYK_JSON:
                return this.normalizeSnykJson(rawResult, options);
            default:
                throw new BadRequestException(`Unsupported format: ${sourceFormat}`);
        }
    }

    /**
     * Detect the schema version from raw Trivy result
     */
    detectTrivySchemaVersion(rawResult: any): string {
        if (rawResult.SchemaVersion) {
            return String(rawResult.SchemaVersion);
        }
        // Default to schema version 2 for newer Trivy versions
        return '2';
    }

    /**
     * Normalize Trivy JSON format
     */
    private normalizeTrivyJson(
        rawResult: any,
        options?: { schemaVersion?: string; scannerVersion?: string },
    ): NormalizedScanResult {
        if (!rawResult) {
            throw new BadRequestException('Empty scan result');
        }

        const schemaVersion = options?.schemaVersion || this.detectTrivySchemaVersion(rawResult);
        const scannerVersion = options?.scannerVersion || rawResult.Metadata?.ReportVersion;

        // Find appropriate schema mapping
        const schemaMapping = TRIVY_SCHEMA_MAPPINGS.find(
            m => m.schemaVersion === schemaVersion,
        ) || TRIVY_SCHEMA_MAPPINGS[0];

        const vulnerabilities: NormalizedVulnerability[] = [];
        const results = rawResult.Results || [];

        // Track severity counts
        const severityCounts: Record<string, number> = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            UNKNOWN: 0,
        };
        const packageTypeCounts: Record<string, number> = {};
        let fixableCount = 0;

        for (const target of results) {
            const vulns = target.Vulnerabilities || [];
            const targetType = this.detectPackageEcosystem(target.Type || target.Class);

            for (const vuln of vulns) {
                const normalizedVuln = this.normalizeTrivyVulnerability(
                    vuln,
                    target,
                    targetType,
                    schemaMapping,
                );
                vulnerabilities.push(normalizedVuln);

                // Update counts
                severityCounts[normalizedVuln.severity]++;
                packageTypeCounts[targetType] = (packageTypeCounts[targetType] || 0) + 1;
                if (normalizedVuln.packageInfo.fixedVersion) {
                    fixableCount++;
                }
            }
        }

        return {
            schemaVersion: CURRENT_SCHEMA_VERSION,
            scanner: {
                name: 'trivy',
                version: scannerVersion || 'unknown',
                originalSchemaVersion: schemaVersion,
            },
            artifact: {
                name: rawResult.ArtifactName || 'unknown',
                type: this.mapArtifactType(rawResult.ArtifactType),
                digest: rawResult.Metadata?.ImageID,
                imageId: rawResult.Metadata?.ImageID,
            },
            scanMetadata: {
                scannedAt: new Date(),
                duration: undefined,
                config: rawResult.Metadata?.ScanOptions,
            },
            vulnerabilities,
            summary: {
                total: vulnerabilities.length,
                bySeverity: severityCounts,
                byPackageType: packageTypeCounts,
                fixable: fixableCount,
            },
        };
    }

    /**
     * Normalize a single Trivy vulnerability
     */
    private normalizeTrivyVulnerability(
        vuln: any,
        target: any,
        ecosystem: PackageEcosystem,
        _schemaMapping: any,
    ): NormalizedVulnerability {
        return {
            id: `${vuln.VulnerabilityID}-${vuln.PkgName}-${vuln.InstalledVersion}`,
            cveId: vuln.VulnerabilityID,
            title: vuln.Title || vuln.VulnerabilityID,
            description: vuln.Description || '',
            severity: this.mapSeverity(vuln.Severity),
            cvssV2Score: this.extractCvssScore(vuln, 'V2'),
            cvssV2Vector: this.extractCvssVector(vuln, 'V2'),
            cvssV3Score: this.extractCvssScore(vuln, 'V3'),
            cvssV3Vector: this.extractCvssVector(vuln, 'V3'),
            cweIds: vuln.CweIDs || [],
            references: vuln.References || [],
            packageInfo: {
                name: vuln.PkgName,
                version: vuln.InstalledVersion,
                fixedVersion: vuln.FixedVersion || undefined,
                ecosystem,
                path: vuln.PkgPath || target.Target,
            },
            layerInfo: vuln.Layer
                ? {
                    digest: vuln.Layer.Digest,
                    diffId: vuln.Layer.DiffID,
                    createdBy: vuln.Layer.CreatedBy,
                }
                : undefined,
            publishedAt: vuln.PublishedDate ? new Date(vuln.PublishedDate) : undefined,
            lastModifiedAt: vuln.LastModifiedDate ? new Date(vuln.LastModifiedDate) : undefined,
            metadata: {
                datasources: vuln.DataSource ? [vuln.DataSource.ID || vuln.DataSource.Name] : [],
                exploitAvailable: vuln.Exploit !== undefined,
                patchAvailable: !!vuln.FixedVersion,
            },
        };
    }

    /**
     * Normalize Trivy SARIF format
     */
    private normalizeTrivySarif(
        rawResult: any,
        _options?: { schemaVersion?: string; scannerVersion?: string },
    ): NormalizedScanResult {
        if (!rawResult || !rawResult.runs || !rawResult.runs[0]) {
            throw new BadRequestException('Invalid SARIF format');
        }

        const run = rawResult.runs[0];
        const tool = run.tool?.driver || {};
        const rules = tool.rules || [];
        const rulesMap = new Map(rules.map((r: any) => [r.id, r]));

        const vulnerabilities: NormalizedVulnerability[] = [];
        const severityCounts: Record<string, number> = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            UNKNOWN: 0,
        };
        let fixableCount = 0;

        const results = run.results || [];

        for (const finding of results) {
            const rule: any = rulesMap.get(finding.ruleId) || {};
            const properties: any = rule.properties || {};

            const pkgInfo = this.extractPackageFromSarif(finding, properties);
            const severity = this.mapSarifSeverity(properties.security_severity);

            const normalizedVuln: NormalizedVulnerability = {
                id: `${finding.ruleId}-${pkgInfo.name}-${pkgInfo.version}`,
                cveId: finding.ruleId,
                title: rule.shortDescription?.text || rule.name || finding.ruleId,
                description: rule.fullDescription?.text || '',
                severity,
                cvssV3Score: properties.cvssV3_score,
                cvssV3Vector: properties.cvssV3_vector,
                cweIds: properties.cwe_ids || [],
                references: (rule.helpUri ? [rule.helpUri] : []).concat(properties.references || []),
                packageInfo: {
                    name: pkgInfo.name,
                    version: pkgInfo.version,
                    fixedVersion: properties.fixedVersion,
                    ecosystem: 'other',
                    path: finding.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
                },
                publishedAt: properties.publishedDate ? new Date(properties.publishedDate) : undefined,
                metadata: {
                    datasources: ['sarif'],
                    patchAvailable: !!properties.fixedVersion,
                },
            };

            vulnerabilities.push(normalizedVuln);
            severityCounts[severity]++;
            if (normalizedVuln.packageInfo.fixedVersion) {
                fixableCount++;
            }
        }

        return {
            schemaVersion: CURRENT_SCHEMA_VERSION,
            scanner: {
                name: tool.name || 'trivy',
                version: tool.version || 'unknown',
                originalSchemaVersion: rawResult.version,
            },
            artifact: {
                name: run.originalUriBaseIds?.ROOTPATH?.uri || 'unknown',
                type: 'other',
            },
            scanMetadata: {
                scannedAt: new Date(),
            },
            vulnerabilities,
            summary: {
                total: vulnerabilities.length,
                bySeverity: severityCounts,
                byPackageType: {},
                fixable: fixableCount,
            },
        };
    }

    /**
     * Normalize Grype JSON format (placeholder - can be extended)
     */
    private normalizeGrypeJson(
        rawResult: any,
        _options?: { schemaVersion?: string; scannerVersion?: string },
    ): NormalizedScanResult {
        // Grype format normalization
        const vulnerabilities: NormalizedVulnerability[] = [];
        const matches = rawResult.matches || [];

        for (const match of matches) {
            const vuln = match.vulnerability || {};
            const artifact = match.artifact || {};

            vulnerabilities.push({
                id: `${vuln.id}-${artifact.name}-${artifact.version}`,
                cveId: vuln.id,
                title: vuln.id,
                description: vuln.description || '',
                severity: this.mapSeverity(vuln.severity),
                cvssV3Score: vuln.cvss?.[0]?.metrics?.baseScore,
                cweIds: vuln.cweIds || [],
                references: vuln.urls || [],
                packageInfo: {
                    name: artifact.name,
                    version: artifact.version,
                    fixedVersion: vuln.fix?.versions?.[0],
                    ecosystem: this.detectPackageEcosystem(artifact.type),
                    path: artifact.locations?.[0]?.path,
                },
                metadata: {
                    datasources: ['grype'],
                    patchAvailable: vuln.fix?.state === 'fixed',
                },
            });
        }

        const severityCounts = vulnerabilities.reduce(
            (acc, v) => {
                acc[v.severity]++;
                return acc;
            },
            { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
        );

        return {
            schemaVersion: CURRENT_SCHEMA_VERSION,
            scanner: {
                name: 'grype',
                version: rawResult.descriptor?.version || 'unknown',
            },
            artifact: {
                name: rawResult.source?.target || 'unknown',
                type: this.mapArtifactType(rawResult.source?.type),
            },
            scanMetadata: {
                scannedAt: new Date(),
            },
            vulnerabilities,
            summary: {
                total: vulnerabilities.length,
                bySeverity: severityCounts,
                byPackageType: {},
                fixable: vulnerabilities.filter(v => v.packageInfo.fixedVersion).length,
            },
        };
    }

    /**
     * Normalize Snyk JSON format (placeholder - can be extended)
     */
    private normalizeSnykJson(
        rawResult: any,
        _options?: { schemaVersion?: string; scannerVersion?: string },
    ): NormalizedScanResult {
        const vulnerabilities: NormalizedVulnerability[] = [];
        const vulns = rawResult.vulnerabilities || [];

        for (const vuln of vulns) {
            vulnerabilities.push({
                id: `${vuln.id}-${vuln.packageName}-${vuln.version}`,
                cveId: vuln.identifiers?.CVE?.[0] || vuln.id,
                title: vuln.title || vuln.id,
                description: vuln.description || '',
                severity: this.mapSeverity(vuln.severity),
                cvssV3Score: vuln.cvssScore,
                cweIds: vuln.identifiers?.CWE || [],
                references: vuln.references?.map((r: any) => r.url) || [],
                packageInfo: {
                    name: vuln.packageName,
                    version: vuln.version,
                    fixedVersion: vuln.fixedIn?.[0],
                    ecosystem: this.detectPackageEcosystem(vuln.packageManager),
                    path: vuln.from?.join(' > '),
                },
                metadata: {
                    datasources: ['snyk'],
                    exploitAvailable: vuln.exploit !== undefined,
                    patchAvailable: !!vuln.fixedIn?.length,
                },
            });
        }

        const severityCounts = vulnerabilities.reduce(
            (acc, v) => {
                acc[v.severity]++;
                return acc;
            },
            { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
        );

        return {
            schemaVersion: CURRENT_SCHEMA_VERSION,
            scanner: {
                name: 'snyk',
                version: 'unknown',
            },
            artifact: {
                name: rawResult.projectName || 'unknown',
                type: 'other',
            },
            scanMetadata: {
                scannedAt: new Date(),
            },
            vulnerabilities,
            summary: {
                total: vulnerabilities.length,
                bySeverity: severityCounts,
                byPackageType: {},
                fixable: vulnerabilities.filter(v => v.packageInfo.fixedVersion).length,
            },
        };
    }

    // Helper methods

    private mapSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL':
                return 'CRITICAL';
            case 'HIGH':
                return 'HIGH';
            case 'MEDIUM':
                return 'MEDIUM';
            case 'LOW':
                return 'LOW';
            default:
                return 'UNKNOWN';
        }
    }

    private mapSarifSeverity(score: string | number | undefined): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' {
        const numScore = typeof score === 'string' ? parseFloat(score) : score;
        if (numScore === undefined) return 'UNKNOWN';
        if (numScore >= 9.0) return 'CRITICAL';
        if (numScore >= 7.0) return 'HIGH';
        if (numScore >= 4.0) return 'MEDIUM';
        if (numScore > 0) return 'LOW';
        return 'UNKNOWN';
    }

    private extractCvssScore(vuln: any, version: 'V2' | 'V3'): number | undefined {
        const cvss = vuln.CVSS;
        if (!cvss) return undefined;

        const scoreKey = `${version}Score`;
        if (cvss.nvd?.[scoreKey]) return cvss.nvd[scoreKey];
        if (cvss.redhat?.[scoreKey]) return cvss.redhat[scoreKey];
        return undefined;
    }

    private extractCvssVector(vuln: any, version: 'V2' | 'V3'): string | undefined {
        const cvss = vuln.CVSS;
        if (!cvss) return undefined;

        const vectorKey = `${version}Vector`;
        if (cvss.nvd?.[vectorKey]) return cvss.nvd[vectorKey];
        if (cvss.redhat?.[vectorKey]) return cvss.redhat[vectorKey];
        return undefined;
    }

    private detectPackageEcosystem(type: string): PackageEcosystem {
        const typeMap: Record<string, PackageEcosystem> = {
            'npm': 'npm',
            'node-pkg': 'npm',
            'yarn': 'npm',
            'pip': 'pip',
            'pipenv': 'pip',
            'poetry': 'pip',
            'maven': 'maven',
            'gradle': 'gradle',
            'nuget': 'nuget',
            'dotnet-core': 'nuget',
            'go': 'go',
            'gomod': 'go',
            'gobinary': 'go',
            'cargo': 'cargo',
            'rust': 'cargo',
            'composer': 'composer',
            'gem': 'gem',
            'bundler': 'gem',
            'alpine': 'alpine',
            'apk': 'alpine',
            'debian': 'debian',
            'dpkg': 'debian',
            'ubuntu': 'ubuntu',
            'redhat': 'redhat',
            'rpm': 'redhat',
            'centos': 'centos',
            'amazon-linux': 'amazon-linux',
            'oracle-linux': 'oracle-linux',
            'photon': 'photon',
            'suse': 'suse',
        };

        return typeMap[type?.toLowerCase()] || 'other';
    }

    private mapArtifactType(type: string): ArtifactType {
        const typeMap: Record<string, ArtifactType> = {
            'container_image': 'container_image',
            'image': 'container_image',
            'filesystem': 'filesystem',
            'fs': 'filesystem',
            'repository': 'repository',
            'repo': 'repository',
            'vm': 'vm_image',
            'rootfs': 'rootfs',
            'sbom': 'sbom',
        };

        return typeMap[type?.toLowerCase()] || 'other';
    }

    private extractPackageFromSarif(
        finding: any,
        properties: any,
    ): { name: string; version: string } {
        if (properties.pkgName && properties.pkgVersion) {
            return { name: properties.pkgName, version: properties.pkgVersion };
        }

        const message = finding.message?.text || '';
        const match = message.match(/Package:\s*(\S+)\s+Version:\s*(\S+)/i);

        if (match) {
            return { name: match[1], version: match[2] };
        }

        return { name: 'unknown', version: 'unknown' };
    }
}
