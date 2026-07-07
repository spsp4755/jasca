import { BadRequestException } from '@nestjs/common';
import { SarifParserService } from './sarif-parser.service';

describe('SarifParserService', () => {
    const parser = new SarifParserService();

    const semgrepSarif = {
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'Semgrep',
                        version: '1.99.0',
                        rules: [
                            {
                                id: 'javascript.express.security.injection.tainted-sql-string',
                                name: 'tainted-sql-string',
                                shortDescription: { text: 'SQL Injection via tainted string' },
                                helpUri: 'https://semgrep.dev/r/javascript.express.security.injection.tainted-sql-string',
                                defaultConfiguration: { level: 'error' },
                                properties: {
                                    'security-severity': '8.8',
                                    tags: ['security', 'external/cwe/cwe-89', 'owasp-a03'],
                                },
                            },
                            {
                                id: 'javascript.lang.security.audit.hardcoded-secret',
                                shortDescription: { text: 'Hardcoded secret' },
                                defaultConfiguration: { level: 'warning' },
                                properties: { tags: ['CWE-798: Use of Hard-coded Credentials'] },
                            },
                        ],
                    },
                },
                results: [
                    {
                        ruleId: 'javascript.express.security.injection.tainted-sql-string',
                        level: 'error',
                        message: { text: 'User input flows into SQL query' },
                        locations: [
                            {
                                physicalLocation: {
                                    artifactLocation: { uri: 'src/routes/users.ts' },
                                    region: { startLine: 42 },
                                },
                            },
                        ],
                    },
                    {
                        ruleId: 'javascript.lang.security.audit.hardcoded-secret',
                        level: 'warning',
                        message: { text: 'Secret found' },
                        locations: [
                            {
                                physicalLocation: {
                                    artifactLocation: { uri: 'src/config.ts' },
                                    region: { startLine: 7 },
                                },
                            },
                        ],
                    },
                    {
                        ruleId: 'javascript.lang.security.audit.hardcoded-secret',
                        level: 'warning',
                        message: { text: 'Suppressed finding' },
                        suppressions: [{ kind: 'inSource' }],
                        locations: [
                            {
                                physicalLocation: {
                                    artifactLocation: { uri: 'src/legacy.ts' },
                                    region: { startLine: 1 },
                                },
                            },
                        ],
                    },
                ],
            },
        ],
    };

    it('parses semgrep SARIF into ParsedScanResult', () => {
        const result = parser.parse(semgrepSarif);

        expect(result.trivyVersion).toBe('Semgrep-1.99.0');
        expect(result.artifactType).toBe('sarif');
        // suppressed finding is skipped
        expect(result.vulnerabilities).toHaveLength(2);

        const [sqli, secret] = result.vulnerabilities;
        expect(sqli.cveId).toBe('SEMGREP-javascript.express.security.injection.tainted-sql-string');
        expect(sqli.severity).toBe('HIGH'); // security-severity 8.8
        expect(sqli.cvssScore).toBe(8.8);
        expect(sqli.cweIds).toEqual(['CWE-89']);
        expect(sqli.pkgName).toBe('src/routes/users.ts');
        expect(sqli.pkgVersion).toBe('L42');

        expect(secret.severity).toBe('MEDIUM'); // level: warning
        expect(secret.cweIds).toEqual(['CWE-798']);
    });

    it('keeps CVE-style rule ids unprefixed', () => {
        const sarif = {
            version: '2.1.0',
            runs: [
                {
                    tool: { driver: { name: 'grype', rules: [] } },
                    results: [
                        {
                            ruleId: 'CVE-2024-12345',
                            level: 'error',
                            message: { text: 'vulnerable dependency' },
                        },
                    ],
                },
            ],
        };

        const result = parser.parse(sarif);
        expect(result.vulnerabilities[0].cveId).toBe('CVE-2024-12345');
    });

    it('parses findings across multiple runs', () => {
        const sarif = {
            version: '2.1.0',
            runs: [
                {
                    tool: { driver: { name: 'toolA' } },
                    results: [{ ruleId: 'rule-1', level: 'note', message: { text: 'a' } }],
                },
                {
                    tool: { driver: { name: 'toolB' } },
                    results: [{ ruleId: 'rule-2', level: 'error', message: { text: 'b' } }],
                },
            ],
        };

        const result = parser.parse(sarif);
        expect(result.vulnerabilities.map((v) => v.cveId)).toEqual(['TOOLA-rule-1', 'TOOLB-rule-2']);
    });

    it('rejects non-SARIF payloads', () => {
        expect(() => parser.parse({})).toThrow(BadRequestException);
        expect(() => parser.parse(null)).toThrow(BadRequestException);
        expect(() => parser.parse({ runs: [] })).toThrow(BadRequestException);
    });

    it('exposes the tool name for scanner attribution', () => {
        expect(parser.getToolName(semgrepSarif)).toBe('semgrep');
        expect(parser.getToolName({})).toBe('sarif');
    });
});
