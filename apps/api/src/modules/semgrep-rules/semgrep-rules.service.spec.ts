import { BadRequestException } from '@nestjs/common';
import { SemgrepRulesService } from './semgrep-rules.service';

describe('SemgrepRulesService.validateDto', () => {
    const service = new SemgrepRulesService({} as any);

    const validYaml = `rules:
  - id: company.no-eval
    message: eval() 사용 금지
    severity: ERROR
    languages: [javascript]
    pattern: eval(...)
`;

    it('accepts a valid semgrep rule file', () => {
        expect(() => service.validateDto({ name: 'no-eval', yaml: validYaml })).not.toThrow();
    });

    it('rejects broken YAML', () => {
        expect(() => service.validateDto({ name: 'x', yaml: 'rules:\n  - id: [broken' }))
            .toThrow(BadRequestException);
    });

    it('rejects files without a rules array', () => {
        expect(() => service.validateDto({ name: 'x', yaml: 'foo: bar' })).toThrow(/rules 배열/);
    });

    it('rejects rules missing required fields', () => {
        const missingMessage = `rules:
  - id: company.rule
    severity: ERROR
    languages: [python]
    pattern: foo(...)
`.replace('    message: x\n', '');
        expect(() => service.validateDto({
            name: 'x',
            yaml: missingMessage,
        })).toThrow(/message/);

        expect(() => service.validateDto({
            name: 'x',
            yaml: `rules:\n  - id: r\n    message: m\n    severity: NOPE\n    languages: [python]\n    pattern: foo(...)\n`,
        })).toThrow(/severity/);

        expect(() => service.validateDto({
            name: 'x',
            yaml: `rules:\n  - id: r\n    message: m\n    severity: ERROR\n    languages: [python]\n`,
        })).toThrow(/pattern/);
    });

    it('rejects empty name or yaml', () => {
        expect(() => service.validateDto({ name: ' ', yaml: validYaml })).toThrow(/이름/);
        expect(() => service.validateDto({ name: 'x', yaml: '' })).toThrow(/YAML/);
    });
});
