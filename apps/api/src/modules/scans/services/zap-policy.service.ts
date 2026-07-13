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
    targetProfiles: ZapTargetProfile[];
}

export interface ZapTargetProfile {
    id: string;
    name: string;
    enabled: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
    maxScanDurationMinutes: number;
    defaultRiskThresholdForNotification: string;
}

@Injectable()
export class ZapPolicyService {
    validateTargetUrl(targetUrl: string, settings: ZapSettings, profileId?: string): URL {
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

        const profile = this.getTargetProfile(settings, profileId);
        if (!profile.allowedTargetPatterns.some((pattern) => this.matchesPattern(parsed, pattern))) {
            throw new BadRequestException('ZAP target URL is not allowed by the selected profile.');
        }

        if (profile.blockedTargetPatterns.some((pattern) => this.matchesPattern(parsed, pattern))) {
            throw new BadRequestException('ZAP target URL is blocked by the selected profile.');
        }

        return parsed;
    }

    getTargetProfile(settings: ZapSettings, profileId?: string): ZapTargetProfile {
        const profile = (settings.targetProfiles || []).find((item) => item.id === profileId);
        if (!profile || !profile.enabled) {
            throw new BadRequestException('ZAP target profile is unavailable.');
        }

        if (!profile.name.trim()
            || !Array.isArray(profile.allowedTargetPatterns)
            || profile.allowedTargetPatterns.length === 0
            || !Array.isArray(profile.blockedTargetPatterns)
            || !Number.isFinite(profile.maxScanDurationMinutes)
            || profile.maxScanDurationMinutes < 1) {
            throw new BadRequestException('ZAP target profile is invalid.');
        }

        return profile;
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
