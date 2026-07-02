import { BadRequestException, Injectable, Logger, OnModuleDestroy, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import { Severity, VulnPortalIntelType, VulnPortalSyncStatus } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { SettingsService } from '../settings/settings.service';

export interface VulnPortalSettings {
    enabled: boolean;
    baseUrl: string;
    apiKey?: string;
    syncIntervalMinutes: number;
    syncVulnerabilities: boolean;
    syncKev: boolean;
    syncEol: boolean;
    requestTimeoutSeconds: number;
    maxPagesPerSync: number;
    allowInsecureTls: boolean;
    lastSyncAt?: string | null;
    lastSyncResult?: {
        success: boolean;
        message: string;
        vulnerabilities: number;
        kev: number;
        eol: number;
        finishedAt: string;
    } | null;
}

interface VulnPortalPage<T> {
    data: T[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
}

interface SyncCounters {
    vulnerabilities: number;
    kev: number;
    eol: number;
}

const SETTINGS_KEY = 'vulnPortal';
const MASKED_SECRET = '********';

const defaultSettings: VulnPortalSettings = {
    enabled: false,
    baseUrl: process.env.VULN_PORTAL_BASE_URL || '',
    apiKey: process.env.VULN_PORTAL_API_KEY || '',
    syncIntervalMinutes: Number(process.env.VULN_PORTAL_SYNC_INTERVAL_MINUTES || 60),
    syncVulnerabilities: true,
    syncKev: true,
    syncEol: true,
    requestTimeoutSeconds: 30,
    maxPagesPerSync: 100,
    allowInsecureTls: false,
    lastSyncAt: null,
    lastSyncResult: null,
};

@Injectable()
export class VulnPortalService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(VulnPortalService.name);
    private syncTimer?: NodeJS.Timeout;
    private syncInProgress = false;

    constructor(
        private readonly prisma: PrismaService,
        private readonly settingsService: SettingsService,
    ) { }

    async onModuleInit() {
        await this.rescheduleSync();
    }

    onModuleDestroy() {
        if (this.syncTimer) clearInterval(this.syncTimer);
    }

    async getSettings(maskSecret = true): Promise<VulnPortalSettings> {
        const stored = await this.settingsService.get(SETTINGS_KEY) as Partial<VulnPortalSettings> | null;
        const merged = this.normalizeSettings({ ...defaultSettings, ...(stored || {}) });
        if (maskSecret && merged.apiKey) {
            return { ...merged, apiKey: MASKED_SECRET };
        }
        return merged;
    }

    async updateSettings(input: Partial<VulnPortalSettings>): Promise<VulnPortalSettings> {
        const current = await this.getSettings(false);
        const nextApiKey = input.apiKey === undefined || input.apiKey === MASKED_SECRET
            ? current.apiKey
            : input.apiKey;
        const next = this.normalizeSettings({
            ...current,
            ...input,
            apiKey: nextApiKey,
        });

        await this.settingsService.set(SETTINGS_KEY, next);
        await this.rescheduleSync();
        return this.getSettings(true);
    }

    async testConnection(input?: Partial<VulnPortalSettings>) {
        const base = await this.getSettings(false);
        const settings = this.normalizeSettings({
            ...base,
            ...(input || {}),
            apiKey: input?.apiKey === MASKED_SECRET ? base.apiKey : input?.apiKey ?? base.apiKey,
        });

        const started = Date.now();
        const health = await this.fetchJson(settings, '/api/health', false).catch((error: Error) => ({
            ok: false,
            error: error.message,
        }));
        const sample = await this.fetchJson<VulnPortalPage<unknown>>(settings, '/api/v1/vulnerabilities?limit=1');

        return {
            success: true,
            message: 'vuln-portal API 연결에 성공했습니다.',
            durationMs: Date.now() - started,
            health,
            sample: {
                total: sample.total ?? 0,
                returned: Array.isArray(sample.data) ? sample.data.length : 0,
            },
        };
    }

    async syncNow() {
        if (this.syncInProgress) {
            throw new BadRequestException('vuln-portal 동기화가 이미 진행 중입니다.');
        }

        const settings = await this.getSettings(false);
        if (!settings.baseUrl || !settings.apiKey) {
            throw new BadRequestException('vuln-portal URL과 API Key를 먼저 설정해야 합니다.');
        }

        this.syncInProgress = true;
        const log = await this.prisma.vulnPortalSyncLog.create({
            data: { status: VulnPortalSyncStatus.RUNNING },
        });

        const counters: SyncCounters = { vulnerabilities: 0, kev: 0, eol: 0 };
        try {
            if (settings.syncVulnerabilities) {
                counters.vulnerabilities = await this.syncVulnerabilities(settings);
            }
            if (settings.syncKev) {
                counters.kev = await this.syncKev(settings);
            }
            if (settings.syncEol) {
                counters.eol = await this.syncEol(settings);
            }

            const message = `동기화 완료: CVE ${counters.vulnerabilities}건, KEV ${counters.kev}건, EOL ${counters.eol}건`;
            const finishedAt = new Date();
            await this.prisma.vulnPortalSyncLog.update({
                where: { id: log.id },
                data: {
                    status: VulnPortalSyncStatus.SUCCESS,
                    finishedAt,
                    vulnerabilities: counters.vulnerabilities,
                    kev: counters.kev,
                    eol: counters.eol,
                    message,
                },
            });
            await this.settingsService.set(SETTINGS_KEY, {
                ...settings,
                lastSyncAt: finishedAt.toISOString(),
                lastSyncResult: { success: true, message, ...counters, finishedAt: finishedAt.toISOString() },
            });
            return { success: true, message, ...counters, finishedAt };
        } catch (error: any) {
            const finishedAt = new Date();
            const message = error?.message || 'vuln-portal 동기화 실패';
            await this.prisma.vulnPortalSyncLog.update({
                where: { id: log.id },
                data: {
                    status: VulnPortalSyncStatus.FAILED,
                    finishedAt,
                    vulnerabilities: counters.vulnerabilities,
                    kev: counters.kev,
                    eol: counters.eol,
                    error: message,
                },
            });
            await this.settingsService.set(SETTINGS_KEY, {
                ...settings,
                lastSyncAt: finishedAt.toISOString(),
                lastSyncResult: { success: false, message, ...counters, finishedAt: finishedAt.toISOString() },
            });
            this.logger.error(`vuln-portal sync failed: ${message}`, error?.stack);
            throw new ServiceUnavailableException(`vuln-portal 동기화 실패: ${message}`);
        } finally {
            this.syncInProgress = false;
        }
    }

    async getStatus() {
        const [settings, latestLog, counts] = await Promise.all([
            this.getSettings(true),
            this.prisma.vulnPortalSyncLog.findFirst({ orderBy: { startedAt: 'desc' } }),
            this.prisma.vulnPortalIntel.groupBy({ by: ['type'], _count: { _all: true } }),
        ]);
        return {
            settings,
            syncInProgress: this.syncInProgress,
            latestLog,
            counts: counts.reduce<Record<string, number>>((acc, row) => {
                acc[row.type] = row._count._all;
                return acc;
            }, {}),
        };
    }

    async listIntel(query: {
        type?: VulnPortalIntelType;
        keyword?: string;
        severity?: Severity;
        limit?: number;
        offset?: number;
    }) {
        const limit = Math.min(100, Math.max(1, query.limit || 25));
        const offset = Math.max(0, query.offset || 0);
        const where: any = {};
        if (query.type) where.type = query.type;
        if (query.severity) where.severity = query.severity;
        if (query.keyword) {
            where.OR = [
                { cveId: { contains: query.keyword, mode: 'insensitive' } },
                { title: { contains: query.keyword, mode: 'insensitive' } },
                { description: { contains: query.keyword, mode: 'insensitive' } },
                { vendor: { contains: query.keyword, mode: 'insensitive' } },
                { product: { contains: query.keyword, mode: 'insensitive' } },
            ];
        }

        const [items, total] = await Promise.all([
            this.prisma.vulnPortalIntel.findMany({
                where,
                orderBy: [{ isKev: 'desc' }, { severity: 'asc' }, { lastSyncedAt: 'desc' }],
                take: limit,
                skip: offset,
            }),
            this.prisma.vulnPortalIntel.count({ where }),
        ]);
        return { items, total, limit, offset };
    }

    async findByCveId(cveId: string) {
        return this.prisma.vulnPortalIntel.findMany({
            where: { cveId: { equals: cveId, mode: 'insensitive' } },
            orderBy: [{ type: 'asc' }, { lastSyncedAt: 'desc' }],
        });
    }

    async getLogs(limit = 20) {
        return this.prisma.vulnPortalSyncLog.findMany({
            orderBy: { startedAt: 'desc' },
            take: Math.min(100, Math.max(1, limit)),
        });
    }

    private async rescheduleSync() {
        if (this.syncTimer) {
            clearInterval(this.syncTimer);
            this.syncTimer = undefined;
        }
        const settings = await this.getSettings(false);
        if (!settings.enabled || settings.syncIntervalMinutes <= 0) return;

        const intervalMs = Math.max(5, settings.syncIntervalMinutes) * 60 * 1000;
        this.syncTimer = setInterval(() => {
            this.syncNow().catch((error: Error) => {
                this.logger.warn(`scheduled vuln-portal sync skipped/failed: ${error.message}`);
            });
        }, intervalMs);
    }

    private async syncVulnerabilities(settings: VulnPortalSettings): Promise<number> {
        let count = 0;
        await this.fetchPaged(settings, '/api/v1/vulnerabilities?limit=100&sort=modifiedAt&order=desc', async (item: any) => {
            const cvss = this.pickBestCvss(item.cvssScores);
            const cpe = Array.isArray(item.cpeMappings) ? item.cpeMappings[0] : undefined;
            const description = this.pickDescription(item.description);
            await this.prisma.vulnPortalIntel.upsert({
                where: { type_externalId: { type: VulnPortalIntelType.VULNERABILITY, externalId: item.cveId } },
                create: {
                    type: VulnPortalIntelType.VULNERABILITY,
                    externalId: item.cveId,
                    cveId: item.cveId,
                    title: item.kevEntry?.vulnerabilityName || item.cveId,
                    description,
                    severity: this.normalizeSeverity(cvss?.baseSeverity),
                    vendor: cpe?.vendor || item.kevEntry?.vendorProject || null,
                    product: cpe?.product || item.kevEntry?.product || null,
                    cvssScore: this.toNumber(cvss?.baseScore),
                    cvssVector: cvss?.vectorString || null,
                    epssScore: this.toNumber(item.epssScore?.score),
                    isKev: Boolean(item.isKev || item.kevEntry),
                    publishedAt: this.toDate(item.publishedAt),
                    modifiedAt: this.toDate(item.modifiedAt),
                    dueDate: this.toDate(item.kevEntry?.dueDate),
                    raw: item,
                },
                update: {
                    title: item.kevEntry?.vulnerabilityName || item.cveId,
                    description,
                    severity: this.normalizeSeverity(cvss?.baseSeverity),
                    vendor: cpe?.vendor || item.kevEntry?.vendorProject || null,
                    product: cpe?.product || item.kevEntry?.product || null,
                    cvssScore: this.toNumber(cvss?.baseScore),
                    cvssVector: cvss?.vectorString || null,
                    epssScore: this.toNumber(item.epssScore?.score),
                    isKev: Boolean(item.isKev || item.kevEntry),
                    publishedAt: this.toDate(item.publishedAt),
                    modifiedAt: this.toDate(item.modifiedAt),
                    dueDate: this.toDate(item.kevEntry?.dueDate),
                    raw: item,
                    lastSyncedAt: new Date(),
                },
            });
            count++;
        });
        return count;
    }

    private async syncKev(settings: VulnPortalSettings): Promise<number> {
        let count = 0;
        await this.fetchPaged(settings, '/api/v1/kev?limit=100&sort=dateAdded&order=desc', async (item: any) => {
            const vuln = item.vulnerability || {};
            const cvss = this.pickBestCvss(vuln.cvssScores);
            const cveId = item.vulnerabilityId || vuln.cveId;
            if (!cveId) return;
            await this.prisma.vulnPortalIntel.upsert({
                where: { type_externalId: { type: VulnPortalIntelType.KEV, externalId: cveId } },
                create: {
                    type: VulnPortalIntelType.KEV,
                    externalId: cveId,
                    cveId,
                    title: item.vulnerabilityName || cveId,
                    description: item.shortDescription || this.pickDescription(vuln.description),
                    severity: this.normalizeSeverity(cvss?.baseSeverity),
                    vendor: item.vendorProject || null,
                    product: item.product || null,
                    cvssScore: this.toNumber(cvss?.baseScore),
                    epssScore: this.toNumber(vuln.epssScore?.score),
                    isKev: true,
                    publishedAt: this.toDate(vuln.publishedAt),
                    modifiedAt: this.toDate(vuln.modifiedAt),
                    dueDate: this.toDate(item.dueDate),
                    raw: item,
                },
                update: {
                    title: item.vulnerabilityName || cveId,
                    description: item.shortDescription || this.pickDescription(vuln.description),
                    severity: this.normalizeSeverity(cvss?.baseSeverity),
                    vendor: item.vendorProject || null,
                    product: item.product || null,
                    cvssScore: this.toNumber(cvss?.baseScore),
                    epssScore: this.toNumber(vuln.epssScore?.score),
                    isKev: true,
                    publishedAt: this.toDate(vuln.publishedAt),
                    modifiedAt: this.toDate(vuln.modifiedAt),
                    dueDate: this.toDate(item.dueDate),
                    raw: item,
                    lastSyncedAt: new Date(),
                },
            });
            count++;
        });
        return count;
    }

    private async syncEol(settings: VulnPortalSettings): Promise<number> {
        let count = 0;
        await this.fetchPaged(settings, '/api/v1/eol?limit=100&sort=eolDate&order=asc', async (item: any) => {
            const externalId = `${item.product || 'unknown'}:${item.cycle || item.id || 'unknown'}`;
            await this.prisma.vulnPortalIntel.upsert({
                where: { type_externalId: { type: VulnPortalIntelType.EOL, externalId } },
                create: {
                    type: VulnPortalIntelType.EOL,
                    externalId,
                    title: `${item.product || 'Unknown'} ${item.cycle || ''}`.trim(),
                    description: item.supportStatus || null,
                    severity: item.isEol ? Severity.HIGH : Severity.UNKNOWN,
                    product: item.product || null,
                    isKev: false,
                    publishedAt: this.toDate(item.releaseDate),
                    eolDate: this.toDate(item.eolDate),
                    raw: item,
                },
                update: {
                    title: `${item.product || 'Unknown'} ${item.cycle || ''}`.trim(),
                    description: item.supportStatus || null,
                    severity: item.isEol ? Severity.HIGH : Severity.UNKNOWN,
                    product: item.product || null,
                    publishedAt: this.toDate(item.releaseDate),
                    eolDate: this.toDate(item.eolDate),
                    raw: item,
                    lastSyncedAt: new Date(),
                },
            });
            count++;
        });
        return count;
    }

    private async fetchPaged<T>(settings: VulnPortalSettings, path: string, onItem: (item: T) => Promise<void>) {
        let page = 1;
        let totalPages = 1;
        const maxPages = Math.max(1, settings.maxPagesPerSync || 100);
        while (page <= totalPages && page <= maxPages) {
            const separator = path.includes('?') ? '&' : '?';
            const response = await this.fetchJson<VulnPortalPage<T>>(settings, `${path}${separator}page=${page}`);
            if (!Array.isArray(response.data)) {
                throw new Error(`Invalid vuln-portal response for ${path}: data array missing`);
            }
            for (const item of response.data) {
                await onItem(item);
            }
            totalPages = Math.max(1, Number(response.totalPages || 1));
            page++;
        }
    }

    private async fetchJson<T = any>(settings: VulnPortalSettings, path: string, requireApiKey = true): Promise<T> {
        if (!settings.baseUrl) throw new Error('vuln-portal URL is empty');
        if (requireApiKey && !settings.apiKey) throw new Error('vuln-portal API Key is empty');

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), Math.max(5, settings.requestTimeoutSeconds) * 1000);
        const baseUrl = settings.baseUrl.replace(/\/+$/, '');
        const url = `${baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
        const previousTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        if (settings.allowInsecureTls) {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        }
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    Accept: 'application/json',
                    ...(requireApiKey ? { 'X-API-Key': settings.apiKey || '' } : {}),
                },
                signal: controller.signal,
            });
            const text = await response.text();
            if (!response.ok) {
                throw new Error(`HTTP ${response.status} ${response.statusText}: ${text.slice(0, 300)}`);
            }
            return text ? JSON.parse(text) as T : {} as T;
        } catch (error: any) {
            if (error?.name === 'AbortError') {
                throw new Error(`vuln-portal request timed out after ${settings.requestTimeoutSeconds}s`);
            }
            throw error;
        } finally {
            clearTimeout(timeout);
            if (settings.allowInsecureTls) {
                if (previousTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
                else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTls;
            }
        }
    }

    private normalizeSettings(input: Partial<VulnPortalSettings>): VulnPortalSettings {
        const interval = Number(input.syncIntervalMinutes || defaultSettings.syncIntervalMinutes);
        const timeout = Number(input.requestTimeoutSeconds || defaultSettings.requestTimeoutSeconds);
        const maxPages = Number(input.maxPagesPerSync || defaultSettings.maxPagesPerSync);
        return {
            ...defaultSettings,
            ...input,
            baseUrl: String(input.baseUrl || '').trim().replace(/\/+$/, ''),
            apiKey: String(input.apiKey || '').trim(),
            enabled: Boolean(input.enabled),
            syncIntervalMinutes: Math.min(1440, Math.max(5, interval)),
            requestTimeoutSeconds: Math.min(300, Math.max(5, timeout)),
            maxPagesPerSync: Math.min(1000, Math.max(1, maxPages)),
            syncVulnerabilities: input.syncVulnerabilities !== false,
            syncKev: input.syncKev !== false,
            syncEol: input.syncEol !== false,
            allowInsecureTls: Boolean(input.allowInsecureTls),
        };
    }

    private pickBestCvss(scores: any[] | undefined) {
        if (!Array.isArray(scores) || scores.length === 0) return undefined;
        return [...scores].sort((a, b) => Number(b.baseScore || 0) - Number(a.baseScore || 0))[0];
    }

    private pickDescription(description: any): string | null {
        if (!description) return null;
        if (typeof description === 'string') return description;
        return description.ko || description.en || JSON.stringify(description);
    }

    private normalizeSeverity(value: unknown): Severity {
        const text = String(value || '').toUpperCase();
        return Object.values(Severity).includes(text as Severity) ? text as Severity : Severity.UNKNOWN;
    }

    private toDate(value: unknown): Date | null {
        if (!value) return null;
        const date = new Date(String(value));
        return Number.isNaN(date.getTime()) ? null : date;
    }

    private toNumber(value: unknown): number | null {
        if (value === null || value === undefined || value === '') return null;
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
    }
}
