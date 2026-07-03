import { BadRequestException } from '@nestjs/common';
import { ZapParserService } from './zap-parser.service';

describe('ZapParserService', () => {
    const service = new ZapParserService();

    it('maps a ZAP JSON report with sites, alerts, and instances to parsed vulnerabilities', () => {
        const parsed = service.parse({
            zapVersion: '2.15.0',
            Metadata: {
                JascaScanEvidence: {
                    targetUrl: 'https://app.example.test',
                },
            },
            site: [
                {
                    '@name': 'https://fallback.example.test',
                    alerts: [
                        {
                            pluginid: '10021',
                            alert: 'X-Content-Type-Options Header Missing',
                            riskdesc: 'Medium (High)',
                            confidence: 'High',
                            desc: '<p>The anti-MIME-sniffing header is missing.</p>',
                            solution: '<p>Set X-Content-Type-Options: nosniff.</p>',
                            reference: '<p>See https://owasp.org/www-project-secure-headers/ and http://example.com/zap.</p>',
                            cweid: '693',
                            wascid: '15',
                            instances: [
                                {
                                    uri: 'https://app.example.test/login',
                                    method: 'GET',
                                    param: 'redirect',
                                    attack: 'https://evil.example.test',
                                    evidence: 'X-Content-Type-Options',
                                },
                            ],
                        },
                    ],
                },
            ],
        });

        expect(parsed).toEqual(expect.objectContaining({
            trivyVersion: 'zap-2.15.0',
            schemaVersion: 'zap-json',
            artifactName: 'https://app.example.test',
            artifactType: 'zap',
        }));
        expect(parsed.vulnerabilities).toEqual([
            expect.objectContaining({
                cveId: 'ZAP-10021',
                title: 'X-Content-Type-Options Header Missing',
                description: 'The anti-MIME-sniffing header is missing.',
                severity: 'MEDIUM',
                references: ['https://owasp.org/www-project-secure-headers/', 'http://example.com/zap'],
                cweIds: ['CWE-693'],
                pkgName: 'https://app.example.test/login',
                pkgVersion: 'GET redirect https://evil.example.test',
                fixedVersion: 'Set X-Content-Type-Options: nosniff.',
                pkgPath: 'https://app.example.test/login',
                layer: expect.objectContaining({
                    scanner: 'zap',
                    confidence: 'High',
                    wascId: '15',
                    method: 'GET',
                    parameter: 'redirect',
                    attack: 'https://evil.example.test',
                    evidence: 'X-Content-Type-Options',
                }),
            }),
        ]);
    });

    it('maps informational risk to UNKNOWN and defaults to one alert instance', () => {
        const parsed = service.parse({
            sites: [
                {
                    '@name': 'https://info.example.test',
                    alerts: [
                        {
                            pluginid: '10027',
                            alert: 'Information Disclosure',
                            risk: 'Informational',
                        },
                    ],
                },
            ],
        });

        expect(parsed.trivyVersion).toBe('zap');
        expect(parsed.vulnerabilities).toHaveLength(1);
        expect(parsed.vulnerabilities[0]).toEqual(expect.objectContaining({
            cveId: 'ZAP-10027',
            severity: 'UNKNOWN',
            pkgName: 'https://info.example.test',
            pkgVersion: 'unknown - -',
            pkgPath: 'https://info.example.test',
        }));
    });

    it('accepts valid ZAP reports with zero alerts', () => {
        const parsed = service.parse({
            site: [
                {
                    '@name': 'https://clean.internal',
                    alerts: [],
                },
            ],
        });

        expect(parsed.artifactName).toBe('https://clean.internal');
        expect(parsed.vulnerabilities).toEqual([]);
    });

    it('keeps separate instances with the same URL and method when param or attack differs', () => {
        const parsed = service.parse({
            site: [
                {
                    '@name': 'https://app.example.test',
                    alerts: [
                        {
                            pluginid: '40012',
                            alert: 'Cross Site Scripting',
                            risk: 'High',
                            instances: [
                                {
                                    uri: 'https://app.example.test/search',
                                    method: 'GET',
                                    param: 'q',
                                    attack: '<script>alert(1)</script>',
                                },
                                {
                                    uri: 'https://app.example.test/search',
                                    method: 'GET',
                                    param: 'page',
                                    attack: 'javascript:alert(1)',
                                },
                            ],
                        },
                    ],
                },
            ],
        });

        expect(parsed.vulnerabilities).toHaveLength(2);
        expect(parsed.vulnerabilities.map((vulnerability) => vulnerability.pkgVersion)).toEqual([
            'GET q <script>alert(1)</script>',
            'GET page javascript:alert(1)',
        ]);
    });

    it('excludes invalid ZAP CWE IDs', () => {
        const cweIds = ['-1', '0', 'abc', ''].map((cweid) => service.parse({
            site: [
                {
                    '@name': 'https://app.example.test',
                    alerts: [
                        {
                            pluginid: '10001',
                            alert: 'Invalid CWE',
                            cweid,
                        },
                    ],
                },
            ],
        }).vulnerabilities[0].cweIds);

        expect(cweIds).toEqual([[], [], [], []]);
    });

    it('extracts href references before stripping HTML tags and decodes entities', () => {
        const parsed = service.parse({
            site: [
                {
                    '@name': 'https://app.example.test',
                    alerts: [
                        {
                            pluginid: '10002',
                            alert: 'Reference Handling',
                            reference: '<a href="https://example.com/a?x=1&amp;y=2">doc</a> https://example.com/a?x=1&amp;y=2.',
                        },
                    ],
                },
            ],
        });

        expect(parsed.vulnerabilities[0].references).toEqual(['https://example.com/a?x=1&y=2']);
    });

    it('rejects empty or invalid ZAP reports', () => {
        expect(() => service.parse(null)).toThrow(BadRequestException);
        expect(() => service.parse({ site: [] })).toThrow(BadRequestException);
    });
});
