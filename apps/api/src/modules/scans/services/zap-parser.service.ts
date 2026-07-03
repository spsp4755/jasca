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
    param?: string;
    attack?: string;
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
            const method = this.stringify(instance.method) || 'unknown';
            const parameter = this.stringify(instance.param);
            const attack = this.stringify(instance.attack);

            return {
                cveId: `ZAP-${pluginId}`,
                title: alert.alert || alert.name || `ZAP-${pluginId}`,
                description: this.cleanText(alert.desc || alert.description),
                severity: this.mapSeverity(alert.risk || alert.riskdesc),
                references: this.extractReferences(alert.reference),
                cweIds: this.extractCweIds(alert),
                pkgName: url,
                pkgVersion: this.buildPkgVersion(method, parameter, attack),
                fixedVersion: this.cleanText(alert.solution),
                pkgPath: url,
                layer: {
                    scanner: 'zap',
                    confidence: alert.confidence,
                    wascId: this.stringify(alert.wascid ?? alert.wascId),
                    method,
                    parameter,
                    attack,
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
        if (!reference) return [];

        const urls = reference.match(/https?:\/\/[^\s<>"']+/gi) || [];
        const hrefUrls = Array.from(reference.matchAll(/href\s*=\s*["']([^"']+)["']/gi))
            .map((match) => match[1])
            .filter((href) => /^https?:\/\//i.test(href));

        return Array.from(new Set([...urls, ...hrefUrls]
            .map((url) => this.decodeHtmlEntities(url).replace(/[),.;]+$/g, '').trim())
            .filter(Boolean)));
    }

    private extractCweIds(alert: ZapAlert): string[] {
        const cweId = this.stringify(alert.cweid ?? alert.cweId);
        if (!cweId || !/^\d+$/.test(cweId)) {
            return [];
        }

        const numericCweId = Number(cweId);
        return numericCweId > 0 ? [`CWE-${numericCweId}`] : [];
    }

    private buildPkgVersion(method: string, parameter?: string, attack?: string): string {
        return `${method} ${parameter || '-'} ${attack || '-'}`.trim();
    }

    private decodeHtmlEntities(value: string): string {
        return value.replace(/&amp;/g, '&');
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
