import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SemgrepScanService } from './semgrep-scan.service';

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
