import { Injectable, ServiceUnavailableException } from '@nestjs/common';

export interface ZapClientOptions {
    baseUrl: string;
    apiKey?: string;
    timeoutMs: number;
}

@Injectable()
export class ZapClientService {
    async getVersion(options: ZapClientOptions): Promise<string> {
        const result = await this.getJson<{ version?: string }>(options, '/JSON/core/view/version/', {});
        return result.version || 'unknown';
    }

    async spiderScan(options: ZapClientOptions, targetUrl: string, contextName?: string): Promise<string> {
        const result = await this.getJson<{ scan?: string }>(options, '/JSON/spider/action/scan/', {
            url: targetUrl,
            ...(contextName ? { contextName, subtreeOnly: 'true' } : {}),
        });
        return result.scan || '';
    }

    async createContext(options: ZapClientOptions, contextName: string): Promise<string> {
        const result = await this.getJson<{ contextId?: string }>(options, '/JSON/context/action/newContext/', { contextName });
        return result.contextId || '';
    }

    async includeInContext(options: ZapClientOptions, contextName: string, regex: string): Promise<void> {
        await this.getJson(options, '/JSON/context/action/includeInContext/', { contextName, regex });
    }

    async removeContext(options: ZapClientOptions, contextName: string): Promise<void> {
        await this.getJson(options, '/JSON/context/action/removeContext/', { contextName });
    }

    async spiderStatus(options: ZapClientOptions, scanId: string): Promise<number> {
        const result = await this.getJson<{ status?: string }>(options, '/JSON/spider/view/status/', { scanId });
        return Number(result.status || 0);
    }

    async activeScan(options: ZapClientOptions, targetUrl: string, contextId?: string): Promise<string> {
        const result = await this.getJson<{ scan?: string }>(options, '/JSON/ascan/action/scan/', {
            url: targetUrl,
            recurse: 'true',
            inScopeOnly: 'true',
            ...(contextId ? { contextId } : {}),
        });
        return result.scan || '';
    }

    async activeStatus(options: ZapClientOptions, scanId: string): Promise<number> {
        const result = await this.getJson<{ status?: string }>(options, '/JSON/ascan/view/status/', { scanId });
        return Number(result.status || 0);
    }

    async alerts(options: ZapClientOptions, targetUrl: string): Promise<any[]> {
        const result = await this.getJson<{ alerts?: any[] }>(options, '/JSON/core/view/alerts/', {
            baseurl: targetUrl,
            start: '0',
            count: '999999',
        });
        return result.alerts || [];
    }

    async stopSpider(options: ZapClientOptions, scanId: string): Promise<void> {
        await this.getJson(options, '/JSON/spider/action/stop/', { scanId });
    }

    async stopActive(options: ZapClientOptions, scanId: string): Promise<void> {
        await this.getJson(options, '/JSON/ascan/action/stop/', { scanId });
    }

    async addRequestHeaderRule(
        options: ZapClientOptions,
        description: string,
        headerName: string,
        headerValue: string,
    ): Promise<void> {
        await this.getJson(options, '/JSON/replacer/action/addRule/', {
            description,
            enabled: 'true',
            matchType: 'REQ_HEADER',
            matchRegex: 'false',
            matchString: headerName,
            replacement: headerValue,
        });
    }

    async removeRule(options: ZapClientOptions, description: string): Promise<void> {
        await this.getJson(options, '/JSON/replacer/action/removeRule/', { description });
    }

    private async getJson<T>(options: ZapClientOptions, path: string, query: Record<string, string>): Promise<T> {
        const url = new URL(path, this.normalizeBaseUrl(options.baseUrl));
        if (options.apiKey) {
            url.searchParams.set('apikey', options.apiKey);
        }

        for (const [key, value] of Object.entries(query)) {
            url.searchParams.set(key, value);
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeoutMs);

        try {
            const response = await fetch(url.toString(), { method: 'GET', signal: controller.signal });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            return await response.json() as T;
        } catch (error) {
            throw new ServiceUnavailableException(`ZAP service call failed: ${(error as Error).message}`);
        } finally {
            clearTimeout(timer);
        }
    }

    private normalizeBaseUrl(baseUrl: string): string {
        return baseUrl.replace(/\/+$/, '');
    }
}
