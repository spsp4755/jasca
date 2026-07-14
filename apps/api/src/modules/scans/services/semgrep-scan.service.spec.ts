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

describe('SemgrepScanService incremental helpers', () => {
    const service = new SemgrepScanService(undefined, undefined);
    const anyService = service as any;

    it('computeManifest hashes files with relative posix paths', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-manifest-'));
        try {
            fs.mkdirSync(path.join(dir, 'src'));
            fs.writeFileSync(path.join(dir, 'src', 'a.ts'), 'aaa');
            fs.writeFileSync(path.join(dir, 'b.ts'), 'bbb');

            const manifest = anyService.computeManifest(dir);
            expect(Object.keys(manifest).sort()).toEqual(['b.ts', 'src/a.ts']);
            expect(manifest['src/a.ts']).toMatch(/^[0-9a-f]{64}$/);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('diffManifests classifies changed, unchanged, and deleted files', () => {
        const diff = anyService.diffManifests(
            { 'same.ts': 'h1', 'mod.ts': 'h2', 'gone.ts': 'h3' },
            { 'same.ts': 'h1', 'mod.ts': 'h2-new', 'new.ts': 'h4' },
        );
        expect(diff.unchanged).toEqual(['same.ts']);
        expect(diff.changed.sort()).toEqual(['mod.ts', 'new.ts']);
        expect(diff.deleted).toEqual(['gone.ts']);
    });

    const sarifWith = (results: any[], rules: any[] = []) => ({
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'Semgrep', rules } }, results }],
    });
    const finding = (ruleId: string, file: string) => ({
        ruleId,
        message: { text: 'm' },
        locations: [{ physicalLocation: { artifactLocation: { uri: file } } }],
    });

    it('mergeBaselineResults appends unchanged-file findings and their rules', () => {
        const newSarif = sarifWith([finding('r-new', 'changed.ts')], [{ id: 'r-new' }]);
        const baseline = sarifWith(
            [finding('r-old', 'same.ts'), finding('r-old', 'changed.ts'), finding('r-old', 'gone.ts')],
            [{ id: 'r-old' }],
        );

        const reused = anyService.mergeBaselineResults(newSarif, baseline, new Set(['same.ts']));

        expect(reused).toBe(1); // only same.ts survives; changed.ts is rescanned, gone.ts dropped
        const run = newSarif.runs[0];
        expect(run.results).toHaveLength(2);
        expect(run.tool.driver.rules.map((r: any) => r.id).sort()).toEqual(['r-new', 'r-old']);
    });

    it('buildSarifFromBaseline keeps only surviving files', () => {
        const baseline = sarifWith([finding('r', 'keep.ts'), finding('r', 'deleted.ts')], [{ id: 'r' }]);
        const rebuilt = anyService.buildSarifFromBaseline(baseline, new Set(['keep.ts']));
        expect(rebuilt.runs[0].results).toHaveLength(1);
        expect(rebuilt.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('keep.ts');
    });

    it('findBaseline picks the newest scan that has a manifest', async () => {
        const prisma: any = {
            scanResult: {
                findMany: jest.fn().mockResolvedValue([
                    { id: 'no-manifest', rawResult: {}, createdAt: new Date() },
                    { id: 'with-manifest', rawResult: { Metadata: { JascaFileManifest: { 'a.ts': 'h' } } }, createdAt: new Date() },
                ]),
            },
        };
        const svc: any = new SemgrepScanService(undefined, prisma);
        const baseline = await svc.findBaseline('p1');
        expect(baseline.id).toBe('with-manifest');
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

describe('SemgrepScanService scan evidence', () => {
    let rulesDir: string;
    let uploadDir: string;
    const originalRulesPath = process.env.SEMGREP_RULES_PATH;

    beforeEach(() => {
        rulesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-evidence-rules-'));
        uploadDir = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-evidence-upload-'));
        process.env.SEMGREP_RULES_PATH = rulesDir;
    });

    afterEach(() => {
        process.env.SEMGREP_RULES_PATH = originalRulesPath;
        fs.rmSync(rulesDir, { recursive: true, force: true });
        fs.rmSync(uploadDir, { recursive: true, force: true });
    });

    it('stores the executed command without the temporary upload path', async () => {
        const sourceFile = path.join(uploadDir, 'app.js');
        fs.writeFileSync(sourceFile, 'const password = "secret";');
        const service: any = new SemgrepScanService(undefined);
        service.runSemgrep = jest.fn().mockResolvedValue(JSON.stringify({ version: '2.1.0', runs: [] }));

        const result = await service.scanUploadedFile(sourceFile);

        expect(result.Metadata.JascaScanEvidence.command).toContain('semgrep scan --sarif');
        expect(result.Metadata.JascaScanEvidence.command).toContain('app.js');
        expect(result.Metadata.JascaScanEvidence.command).not.toContain(uploadDir);
    });

    it('summarizes multiple bundled security rule paths in execution evidence', async () => {
        fs.mkdirSync(path.join(rulesDir, 'javascript', 'security'), { recursive: true });
        fs.mkdirSync(path.join(rulesDir, 'python', 'security'), { recursive: true });
        const sourceFile = path.join(uploadDir, 'app.js');
        fs.writeFileSync(sourceFile, 'const input = process.argv[2];');
        const service: any = new SemgrepScanService(undefined);
        service.runSemgrep = jest.fn().mockResolvedValue(JSON.stringify({ version: '2.1.0', runs: [] }));

        const result = await service.scanUploadedFile(sourceFile, { profile: 'security' });

        expect(result.Metadata.JascaScanEvidence.command).toContain('--config <bundled-rules:2>');
        expect(result.Metadata.JascaScanEvidence.command).not.toContain(`${path.sep}security`);
    });
});
