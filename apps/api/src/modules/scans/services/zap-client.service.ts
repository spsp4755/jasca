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

    async spiderScan(options: ZapClientOptions, targetUrl: string): Promise<string> {
        const result = await this.getJson<{ scan?: string }>(options, '/JSON/spider/action/scan/', { url: targetUrl });
        return result.scan || '';
    }

    async spiderStatus(options: ZapClientOptions, scanId: string): Promise<number> {
        const result = await this.getJson<{ status?: string }>(options, '/JSON/spider/view/status/', { scanId });
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
