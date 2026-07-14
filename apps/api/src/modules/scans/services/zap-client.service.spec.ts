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

    it('starts and stops an in-scope active scan', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({ ok: true, json: async () => ({ scan: '9' }) } as any)
            .mockResolvedValueOnce({ ok: true, json: async () => ({}) } as any);

        const client = new ZapClientService();
        const options = { baseUrl: 'http://zap:8080', apiKey: 'key', timeoutMs: 1000 };
        await expect(client.activeScan(options, 'https://demo.internal')).resolves.toBe('9');
        await client.stopActive(options, '9');

        const activeUrl = (global.fetch as jest.Mock).mock.calls[0][0] as string;
        const stopUrl = (global.fetch as jest.Mock).mock.calls[1][0] as string;
        expect(activeUrl).toContain('/JSON/ascan/action/scan/');
        expect(activeUrl).toContain('recurse=true');
        expect(activeUrl).toContain('inScopeOnly=true');
        expect(stopUrl).toContain('/JSON/ascan/action/stop/');
        expect(stopUrl).toContain('scanId=9');
    });

    it('creates a temporary context and includes only the approved URL expression', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({ ok: true, json: async () => ({ contextId: '3' }) } as any)
            .mockResolvedValueOnce({ ok: true, json: async () => ({}) } as any)
            .mockResolvedValueOnce({ ok: true, json: async () => ({}) } as any);

        const client = new ZapClientService();
        const options = { baseUrl: 'http://zap:8080', timeoutMs: 1000 };
        await expect(client.createContext(options, 'jasca-op-1')).resolves.toBe('3');
        await client.includeInContext(options, 'jasca-op-1', '^https://demo\\.internal(?:/.*)?$');
        await client.removeContext(options, 'jasca-op-1');

        const createUrl = (global.fetch as jest.Mock).mock.calls[0][0] as string;
        const includeUrl = (global.fetch as jest.Mock).mock.calls[1][0] as string;
        const removeUrl = (global.fetch as jest.Mock).mock.calls[2][0] as string;
        expect(createUrl).toContain('/JSON/context/action/newContext/');
        expect(includeUrl).toContain('/JSON/context/action/includeInContext/');
        expect(includeUrl).toContain('contextName=jasca-op-1');
        expect(removeUrl).toContain('/JSON/context/action/removeContext/');
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

    it('adds and removes temporary request header rules', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({}),
        } as any);

        const client = new ZapClientService();
        await client.addRequestHeaderRule(
            { baseUrl: 'http://zap:8080', apiKey: 'key', timeoutMs: 1000 },
            'jasca-auth-op-1',
            'Authorization',
            'Bearer token',
        );
        await client.removeRule(
            { baseUrl: 'http://zap:8080', apiKey: 'key', timeoutMs: 1000 },
            'jasca-auth-op-1',
        );

        const addUrl = (global.fetch as jest.Mock).mock.calls[0][0] as string;
        const removeUrl = (global.fetch as jest.Mock).mock.calls[1][0] as string;
        expect(addUrl).toContain('/JSON/replacer/action/addRule/');
        expect(addUrl).toContain('description=jasca-auth-op-1');
        expect(addUrl).toContain('matchType=REQ_HEADER');
        expect(addUrl).toContain('matchString=Authorization');
        expect(addUrl).toContain('replacement=Bearer+token');
        expect(removeUrl).toContain('/JSON/replacer/action/removeRule/');
        expect(removeUrl).toContain('description=jasca-auth-op-1');
    });

    it('throws a clear error when ZAP is unreachable', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));

        const client = new ZapClientService();
        await expect(client.getVersion({ baseUrl: 'http://zap:8080', apiKey: '', timeoutMs: 1000 }))
            .rejects.toThrow(ServiceUnavailableException);
    });
});
