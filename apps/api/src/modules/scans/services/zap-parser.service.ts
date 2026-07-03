import { BadRequestException, Injectable } from '@nestjs/common';
import { Severity } from '@prisma/client';
import { ParsedScanResult, ParsedVulnerability } from './trivy-parser.service';

type ZapReport = {
    zapVersion?: string;
    Metadata?: {
        JascaScanEvidence?: {
            targetUrl?: string;
        };
    };
    site?: ZapSite[];
    sites?: ZapSite[];
};

type ZapSite = {
    '@name'?: string;
    name?: string;
    alerts?: ZapAlert[];
};

type ZapAlert = {
    pluginid?: string | number;
    pluginId?: string | number;
    alert?: string;
    name?: string;
    risk?: string;
    riskdesc?: string;
    desc?: string;
    description?: string;
    solution?: string;
    reference?: string;
    cweid?: string | number;
    cweId?: string | number;
    wascid?: string | number;
    wascId?: string | number;
    confidence?: string;
    instances?: ZapInstance[];
};

type ZapInstance = {
    uri?: string;
    url?: string;
    method?: string;
    evidence?: string;
};

@Injectable()
export class ZapParserService {
    parse(rawResult: any): ParsedScanResult {
        if (!rawResult || typeof rawResult !== 'object') {
            throw new BadRequestException('Empty ZAP scan result');
        }

        const report = rawResult as ZapReport;
        const sites = this.normalizeSites(report);

        if (sites.length === 0) {
            throw new BadRequestException('Invalid ZAP JSON format');
        }

        const vulnerabilities = sites.flatMap((site) => this.parseSite(site));

        if (vulnerabilities.length === 0) {
            throw new BadRequestException('Invalid ZAP JSON format');
        }

        return {
            trivyVersion: report.zapVersion ? `zap-${report.zapVersion}` : 'zap',
            schemaVersion: 'zap-json',
            artifactName: this.getArtifactName(report, sites),
            artifactType: 'zap',
            vulnerabilities,
        };
    }

    private normalizeSites(report: ZapReport): ZapSite[] {
        const sites = Array.isArray(report.site) ? report.site : report.sites;
        return Array.isArray(sites)
            ? sites.filter((site): site is ZapSite => !!site && typeof site === 'object')
            : [];
    }

    private parseSite(site: ZapSite): ParsedVulnerability[] {
        const alerts = Array.isArray(site.alerts) ? site.alerts : [];
        const siteName = site['@name'] || site.name || 'unknown';

        return alerts.flatMap((alert) => this.parseAlert(alert, siteName));
    }

    private parseAlert(alert: ZapAlert, siteName: string): ParsedVulnerability[] {
        const pluginId = alert.pluginid ?? alert.pluginId;
        if (!pluginId) {
            return [];
        }

        const instances = Array.isArray(alert.instances) && alert.instances.length > 0
            ? alert.instances
            : [{}];

        return instances.map((instance) => {
            const url = instance.uri || instance.url || siteName;

            return {
                cveId: `ZAP-${pluginId}`,
                title: alert.alert || alert.name || `ZAP-${pluginId}`,
                description: this.cleanText(alert.desc || alert.description),
                severity: this.mapSeverity(alert.risk || alert.riskdesc),
                references: this.extractReferences(alert.reference),
                cweIds: this.extractCweIds(alert),
                pkgName: url,
                pkgVersion: instance.method || 'unknown',
                fixedVersion: this.cleanText(alert.solution),
                pkgPath: url,
                layer: {
                    scanner: 'zap',
                    confidence: alert.confidence,
                    wascId: this.stringify(alert.wascid ?? alert.wascId),
                    evidence: instance.evidence,
                },
            };
        });
    }

    private getArtifactName(report: ZapReport, sites: ZapSite[]): string {
        const targetUrl = report.Metadata?.JascaScanEvidence?.targetUrl;
        if (typeof targetUrl === 'string' && targetUrl.trim()) {
            return targetUrl.trim();
        }

        return sites.find((site) => site['@name'] || site.name)?.['@name']
            || sites.find((site) => site.name)?.name
            || 'zap-scan';
    }

    private cleanText(value?: string): string | undefined {
        if (!value) return undefined;
        const cleaned = value
            .replace(/<[^>]*>/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();

        return cleaned || undefined;
    }

    private extractReferences(reference?: string): string[] {
        const text = this.cleanText(reference);
        if (!text) return [];

        return (text.match(/https?:\/\/[^\s<>"']+/gi) || [])
            .map((url) => url.replace(/[),.;]+$/g, ''));
    }

    private extractCweIds(alert: ZapAlert): string[] {
        const cweId = this.stringify(alert.cweid ?? alert.cweId);
        return cweId ? [`CWE-${cweId}`] : [];
    }

    private stringify(value?: string | number): string | undefined {
        if (value === undefined || value === null) return undefined;
        const text = String(value).trim();
        return text || undefined;
    }

    private mapSeverity(risk?: string): Severity {
        const normalized = risk?.split(/\s|\(/)[0]?.toUpperCase();

        switch (normalized) {
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
}
