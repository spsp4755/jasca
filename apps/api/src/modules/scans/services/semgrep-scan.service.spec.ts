import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SemgrepScanService } from './semgrep-scan.service';

describe('SemgrepScanService.resolveBundledConfigs', () => {
    let rulesDir: string;
    let service: SemgrepScanService;
    const originalEnv = process.env.SEMGREP_RULES_PATH;

    beforeAll(() => {
        rulesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-bundled-'));
        // fake bundled rules tree: javascript/lang/security, python/lang, dockerfile/security
        fs.mkdirSync(path.join(rulesDir, 'javascript', 'lang', 'security'), { recursive: true });
        fs.mkdirSync(path.join(rulesDir, 'python', 'lang'), { recursive: true });
        fs.mkdirSync(path.join(rulesDir, 'dockerfile', 'security'), { recursive: true });
        process.env.SEMGREP_RULES_PATH = rulesDir;
        service = new SemgrepScanService(undefined);
    });

    afterAll(() => {
        process.env.SEMGREP_RULES_PATH = originalEnv;
        fs.rmSync(rulesDir, { recursive: true, force: true });
    });

    const resolve = (options: any) => (service as any).resolveBundledConfigs(options);

    it('defaults to the whole bundled ruleset', () => {
        expect(resolve({})).toEqual([rulesDir]);
    });

    it('custom-only returns no bundled configs', () => {
        expect(resolve({ profile: 'custom-only' })).toEqual([]);
    });

    it('limits to existing language directories', () => {
        expect(resolve({ languages: ['javascript', 'PYTHON'] })).toEqual([
            path.join(rulesDir, 'javascript'),
            path.join(rulesDir, 'python'),
        ]);
    });

    it('rejects unknown languages with the available list', () => {
        expect(() => resolve({ languages: ['cobol'] })).toThrow(/지원하지 않는 언어/);
    });

    it('security profile collects nested security dirs', () => {
        expect(resolve({ profile: 'security' }).sort()).toEqual([
            path.join(rulesDir, 'dockerfile', 'security'),
            path.join(rulesDir, 'javascript', 'lang', 'security'),
        ].sort());
    });

    it('security profile falls back to the base when no security dir exists', () => {
        expect(resolve({ profile: 'security', languages: ['python'] })).toEqual([
            path.join(rulesDir, 'python'),
        ]);
    });
});

describe('SemgrepScanService.writeCustomRules', () => {
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-rules-test-'));
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('writes active custom rules and returns the config dir', async () => {
        const rulesService: any = {
            getActiveRuleYamls: jest.fn().mockResolvedValue([
                { id: '1', name: 'no-eval', yaml: 'rules:\n  - id: a\n' },
                { id: '2', name: 'weird name!!', yaml: 'rules:\n  - id: b\n' },
            ]),
        };
        const service = new SemgrepScanService(rulesService);

        const dir = await (service as any).writeCustomRules(tmpDir);

        expect(dir).toBe(path.join(tmpDir, 'custom-rules'));
        const files = fs.readdirSync(dir!).sort();
        expect(files).toEqual(['no-eval.yaml', 'weird-name-.yaml']);
        expect(fs.readFileSync(path.join(dir!, 'no-eval.yaml'), 'utf-8')).toContain('id: a');
    });

    it('returns null when there are no active rules', async () => {
        const rulesService: any = { getActiveRuleYamls: jest.fn().mockResolvedValue([]) };
        const service = new SemgrepScanService(rulesService);

        expect(await (service as any).writeCustomRules(tmpDir)).toBeNull();
    });

    it('returns null and does not fail when the rules service is unavailable', async () => {
        const service = new SemgrepScanService(undefined);
        expect(await (service as any).writeCustomRules(tmpDir)).toBeNull();

        const failing: any = { getActiveRuleYamls: jest.fn().mockRejectedValue(new Error('db down')) };
        const service2 = new SemgrepScanService(failing);
        expect(await (service2 as any).writeCustomRules(tmpDir)).toBeNull();
    });
});
