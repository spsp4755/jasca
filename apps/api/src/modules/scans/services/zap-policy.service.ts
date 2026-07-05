import { BadRequestException, Injectable } from '@nestjs/common';

export interface ZapSettings {
    enabled: boolean;
    zapBaseUrl: string;
    apiKey?: string;
    connectTimeoutSeconds: number;
    maxScanDurationMinutes: number;
    maxConcurrentScans: number;
    allowBaselineScan: boolean;
    allowActiveScan: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
    defaultRiskThresholdForNotification: string;
}

@Injectable()
export class ZapPolicyService {
    validateTargetUrl(targetUrl: string, settings: ZapSettings): URL {
        if (!settings.enabled) {
            throw new BadRequestException('ZAP scanning is disabled by administrator settings.');
        }

        let parsed: URL;
        try {
            parsed = new URL(targetUrl);
        } catch {
            throw new BadRequestException('Invalid ZAP target URL.');
        }

        if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new BadRequestException('ZAP target URL must use http or https.');
        }

        const allowed = settings.allowedTargetPatterns || [];
        if (allowed.length === 0) {
            throw new BadRequestException('ZAP target allowlist is empty. Ask an administrator to configure allowed targets.');
        }

        if (!allowed.some((pattern) => this.matchesPattern(parsed, pattern))) {
            throw new BadRequestException('ZAP target URL is not allowed by administrator policy.');
        }

        const blocked = settings.blockedTargetPatterns || [];
        if (blocked.some((pattern) => this.matchesPattern(parsed, pattern))) {
            throw new BadRequestException('ZAP target URL is blocked by administrator policy.');
        }

        return parsed;
    }

    private matchesPattern(url: URL, pattern: string): boolean {
        const normalized = pattern.trim().toLowerCase().replace(/\/+$/, '');
        if (!normalized) {
            return false;
        }

        const fullUrl = url.href.toLowerCase().replace(/\/+$/, '');
        const host = url.hostname.toLowerCase();

        if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
            return fullUrl === normalized || fullUrl.startsWith(`${normalized}/`);
        }

        if (normalized.startsWith('*.')) {
            return host.endsWith(normalized.slice(1));
        }

        return host === normalized || host.endsWith(`.${normalized}`);
    }
}
