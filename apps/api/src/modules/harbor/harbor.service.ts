import { BadRequestException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { SettingsService } from '../settings/settings.service';

export interface HarborSettings {
    enabled: boolean;
    baseUrl: string;
    username: string;
    password: string;
    allowedProjects: string[];
    defaultProjectId: string;
    webhookSecret: string;
    autoScanOnPush: boolean;
}

export type SafeHarborSettings = Omit<HarborSettings, 'password' | 'webhookSecret'> & {
    passwordConfigured: boolean;
    webhookSecretConfigured: boolean;
};

const SETTINGS_KEY = 'harbor';

const DEFAULT_SETTINGS: HarborSettings = {
    enabled: false,
    baseUrl: '',
    username: '',
    password: '',
    allowedProjects: [],
    defaultProjectId: '',
    webhookSecret: '',
    autoScanOnPush: false,
};

function isMask(value: string) {
    return /^\*+$/.test(value.trim());
}

function isLocalTestHost(hostname: string) {
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

export function normalizeHarborSettings(input: Partial<HarborSettings>): HarborSettings {
    return {
        ...DEFAULT_SETTINGS,
        ...input,
        enabled: Boolean(input.enabled),
        baseUrl: String(input.baseUrl || '').trim().replace(/\/+$/, ''),
        username: String(input.username || '').trim(),
        password: String(input.password || '').trim(),
        allowedProjects: Array.isArray(input.allowedProjects)
            ? input.allowedProjects.map((project) => String(project).trim()).filter(Boolean)
            : [],
        defaultProjectId: String(input.defaultProjectId || '').trim(),
        webhookSecret: String(input.webhookSecret || '').trim(),
        autoScanOnPush: Boolean(input.autoScanOnPush),
    };
}

export function maskHarborSettings(settings: HarborSettings): SafeHarborSettings {
    const { password, webhookSecret, ...safeSettings } = settings;
    return {
        ...safeSettings,
        passwordConfigured: password.length > 0,
        webhookSecretConfigured: webhookSecret.length > 0,
    };
}

@Injectable()
export class HarborService {
    constructor(private readonly settingsService: SettingsService) {}

    async getSettings(): Promise<SafeHarborSettings> {
        return maskHarborSettings(await this.getRawSettings());
    }

    async updateSettings(input: Partial<HarborSettings>): Promise<SafeHarborSettings> {
        const current = await this.getRawSettings();
        const next = normalizeHarborSettings({
            ...current,
            ...input,
            password: this.secretValue(input.password, current.password),
            webhookSecret: this.secretValue(input.webhookSecret, current.webhookSecret),
        });
        this.assertSecureBaseUrl(next.baseUrl);
        await this.settingsService.set(SETTINGS_KEY, next);
        return maskHarborSettings(next);
    }

    async listProjects() {
        const projects = await this.request<unknown[]>('/projects');
        const settings = await this.getRawSettings();
        if (settings.allowedProjects.length === 0) return projects;
        return projects.filter((project: any) => this.isAllowedProject(
            settings,
            String(project?.name || project?.project_name || project?.project_id || ''),
        ));
    }

    async listRepositories(project: string) {
        const settings = await this.getRawSettings();
        this.assertAllowedProject(settings, project);
        return this.request(`/projects/${encodeURIComponent(project)}/repositories`);
    }

    async listArtifacts(project: string, repository: string) {
        const settings = await this.getRawSettings();
        this.assertAllowedProject(settings, project);
        return this.request(
            `/projects/${encodeURIComponent(project)}/repositories/${encodeURIComponent(repository)}/artifacts`,
        );
    }

    async testConnection() {
        const projects = await this.listProjects();
        return { connected: true, projectCount: projects.length };
    }

    private async getRawSettings(): Promise<HarborSettings> {
        return normalizeHarborSettings(await this.settingsService.getRaw(SETTINGS_KEY) as Partial<HarborSettings> || {});
    }

    private secretValue(submitted: unknown, current: string) {
        if (typeof submitted !== 'string' || !submitted.trim() || isMask(submitted)) return current;
        return submitted.trim();
    }

    private assertAllowedProject(settings: HarborSettings, project: string) {
        if (!project.trim() || !this.isAllowedProject(settings, project)) {
            throw new BadRequestException('Harbor project is not allowed');
        }
    }

    private isAllowedProject(settings: HarborSettings, project: string) {
        return settings.allowedProjects.length === 0 || settings.allowedProjects.includes(project);
    }

    private assertSecureBaseUrl(baseUrl: string) {
        if (!baseUrl) throw new BadRequestException('Harbor base URL is required');
        let parsed: URL;
        try {
            parsed = new URL(baseUrl);
        } catch {
            throw new BadRequestException('Harbor base URL is invalid');
        }
        if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocalTestHost(parsed.hostname))) {
            throw new BadRequestException('Harbor base URL must use HTTPS');
        }
    }

    private async request<T = unknown>(path: string): Promise<T> {
        const settings = await this.getRawSettings();
        this.assertSecureBaseUrl(settings.baseUrl);
        const authorization = Buffer.from(`${settings.username}:${settings.password}`).toString('base64');

        try {
            const response = await fetch(`${settings.baseUrl}/api/v2.0${path}`, {
                headers: {
                    Accept: 'application/json',
                    Authorization: `Basic ${authorization}`,
                },
            });
            if (!response.ok) throw new ServiceUnavailableException(`Harbor request failed (${response.status})`);
            return response.json() as Promise<T>;
        } catch (error) {
            if (error instanceof ServiceUnavailableException) throw error;
            throw new ServiceUnavailableException('Harbor request failed');
        }
    }
}
