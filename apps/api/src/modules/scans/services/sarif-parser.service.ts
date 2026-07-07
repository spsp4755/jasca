import { BadRequestException, Injectable } from '@nestjs/common';
import { Severity } from '@prisma/client';
import { ParsedScanResult, ParsedVulnerability } from './trivy-parser.service';

/**
 * Generic SARIF 2.1.0 parser for source-code SAST tools
 * (Semgrep, CodeQL, Checkmarx, Bandit, ESLint, ...).
 * Trivy's own SARIF output is still handled by TrivyParserService (TRIVY_SARIF).
 */
@Injectable()
export class SarifParserService {
    parse(rawResult: any): ParsedScanResult {
        const runs = rawResult?.runs;
        if (!Array.isArray(runs) || runs.length === 0) {
            throw new BadRequestException('Invalid SARIF format: missing runs');
        }

        const firstDriver = runs[0]?.tool?.driver || {};
        const toolName: string = firstDriver.name || 'sarif';

        const vulnerabilities: ParsedVulnerability[] = [];
        for (const run of runs) {
            vulnerabilities.push(...this.parseRun(run));
        }

        return {
            trivyVersion: firstDriver.version ? `${toolName}-${firstDriver.version}` : toolName,
            schemaVersion: String(rawResult.version || '2.1.0'),
            artifactName: this.extractArtifactName(rawResult, toolName),
            artifactType: 'sarif',
            vulnerabilities,
        };
    }

    /** Tool name for scanEvidence/scanner attribution (e.g. "semgrep"). */
    getToolName(rawResult: any): string {
        return String(rawResult?.runs?.[0]?.tool?.driver?.name || 'sarif').toLowerCase();
    }

    private parseRun(run: any): ParsedVulnerability[] {
        const driver = run?.tool?.driver || {};
        const toolName: string = driver.name || 'sarif';
        const rules: any[] = driver.rules || [];
        const rulesMap = new Map(rules.map((r: any) => [r.id, r]));

        const parsed: ParsedVulnerability[] = [];
        for (const finding of run.results || []) {
            // suppressed findings (SARIF-native triage) are not open issues
            if (Array.isArray(finding.suppressions) && finding.suppressions.length > 0) continue;

            const ruleId: string = finding.ruleId || finding.rule?.id || 'unknown-rule';
            const rule: any = rulesMap.get(ruleId) || {};
            const props: any = { ...(rule.properties || {}), ...(finding.properties || {}) };
            const location = finding.locations?.[0]?.physicalLocation;
            const filePath: string = location?.artifactLocation?.uri || 'unknown';
            const startLine: number | undefined = location?.region?.startLine;

            parsed.push({
                cveId: this.buildFindingId(toolName, ruleId),
                title: rule.shortDescription?.text || rule.name || ruleId,
                description: finding.message?.text || rule.fullDescription?.text || rule.help?.text,
                severity: this.mapSeverity(finding, rule, props),
                cvssScore: this.extractSecuritySeverity(props),
                cvssVector: undefined,
                references: rule.helpUri ? [rule.helpUri] : [],
                cweIds: this.extractCweIds(props),
                publishedAt: undefined,
                lastModifiedAt: undefined,
                pkgName: filePath,
                pkgVersion: startLine ? `L${startLine}` : 'unknown',
                fixedVersion: undefined,
                pkgPath: filePath,
                layer: undefined,
            });
        }

        return parsed;
    }

    /**
     * Vulnerability.cveId is globally unique across all scanners, so
     * non-CVE rule ids are namespaced with the tool name (same pattern
     * as ZapParserService's `ZAP-${pluginId}`).
     */
    private buildFindingId(toolName: string, ruleId: string): string {
        if (/^CVE-\d{4}-\d+$/i.test(ruleId)) return ruleId.toUpperCase();
        const prefix = toolName.replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').toUpperCase() || 'SARIF';
        return `${prefix}-${ruleId}`;
    }

    private mapSeverity(finding: any, rule: any, props: any): Severity {
        // GitHub convention: numeric security-severity takes precedence
        const score = this.extractSecuritySeverity(props);
        if (score !== undefined) {
            if (score >= 9) return 'CRITICAL';
            if (score >= 7) return 'HIGH';
            if (score >= 4) return 'MEDIUM';
            return 'LOW';
        }

        // explicit severity strings some tools emit
        const explicit = String(props.severity || props['problem.severity'] || '').toUpperCase();
        if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(explicit)) return explicit as Severity;
        if (explicit === 'ERROR') return 'HIGH';
        if (explicit === 'WARNING') return 'MEDIUM';

        const level = String(finding.level || rule.defaultConfiguration?.level || '').toLowerCase();
        switch (level) {
            case 'error':
                return 'HIGH';
            case 'warning':
                return 'MEDIUM';
            case 'note':
                return 'LOW';
            default:
                return 'UNKNOWN';
        }
    }

    private extractSecuritySeverity(props: any): number | undefined {
        const raw = props['security-severity'] ?? props.security_severity;
        if (raw === undefined || raw === null) return undefined;
        const score = Number(raw);
        return Number.isFinite(score) ? score : undefined;
    }

    private extractCweIds(props: any): string[] {
        const cwes = new Set<string>();
        const candidates: string[] = [
            ...(Array.isArray(props.tags) ? props.tags : []),
            ...(Array.isArray(props.cwe) ? props.cwe : typeof props.cwe === 'string' ? [props.cwe] : []),
        ];
        for (const tag of candidates) {
            // matches "CWE-89", "external/cwe/cwe-89", "CWE-89: SQL Injection"
            const match = String(tag).match(/cwe[-/](\d+)/i);
            if (match) cwes.add(`CWE-${match[1]}`);
        }
        return [...cwes];
    }

    private extractArtifactName(rawResult: any, toolName: string): string {
        const run = rawResult.runs[0];
        const uriBase = run.originalUriBaseIds || {};
        const rootUri = uriBase.SRCROOT?.uri || uriBase.ROOTPATH?.uri || uriBase.PROJECTROOT?.uri;
        return rootUri || `${toolName}-scan`;
    }
}
