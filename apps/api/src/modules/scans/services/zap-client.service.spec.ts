import { ServiceUnavailableException } from '@nestjs/common';
import { ZapClientService } from './zap-client.service';

describe('ZapClientService', () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        originalFetch = global.fetch;
    });

    afterEach(() => {
        global.fetch = originalFetch;
    });

    it('calls ZAP version endpoint with API key', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ version: '2.15.0' }),
        } as any);

        const client = new ZapClientService();
        await expect(client.getVersion({ baseUrl: 'http://zap:8080', apiKey: 'key', timeoutMs: 1000 }))
            .resolves.toBe('2.15.0');

        expect(global.fetch).toHaveBeenCalledWith(
            'http://zap:8080/JSON/core/view/version/?apikey=key',
            expect.objectContaining({ method: 'GET' }),
        );
    });

    it('starts a spider scan with an encoded target URL', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ scan: '7' }),
        } as any);

        const client = new ZapClientService();
        await expect(client.spiderScan({
            baseUrl: 'http://zap:8080/',
            apiKey: '',
            timeoutMs: 1000,
        }, 'https://demo.internal/login?a=1&b=2')).resolves.toBe('7');

        expect(global.fetch).toHaveBeenCalledWith(
            'http://zap:8080/JSON/spider/action/scan/?url=https%3A%2F%2Fdemo.internal%2Flogin%3Fa%3D1%26b%3D2',
            expect.objectContaining({ method: 'GET' }),
        );
    });

    it('loads alerts for a target URL', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ alerts: [{ alert: 'Missing Header' }] }),
        } as any);

        const client = new ZapClientService();
        await expect(client.alerts({ baseUrl: 'http://zap:8080', timeoutMs: 1000 }, 'https://demo.internal'))
            .resolves.toEqual([{ alert: 'Missing Header' }]);

        const calledUrl = (global.fetch as jest.Mock).mock.calls[0][0] as string;
        expect(calledUrl).toContain('/JSON/core/view/alerts/');
        expect(calledUrl).toContain('baseurl=https%3A%2F%2Fdemo.internal');
        expect(calledUrl).toContain('start=0');
        expect(calledUrl).toContain('count=999999');
    });

    it('throws a clear error when ZAP is unreachable', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));

        const client = new ZapClientService();
        await expect(client.getVersion({ baseUrl: 'http://zap:8080', apiKey: '', timeoutMs: 1000 }))
            .rejects.toThrow(ServiceUnavailableException);
    });
});
