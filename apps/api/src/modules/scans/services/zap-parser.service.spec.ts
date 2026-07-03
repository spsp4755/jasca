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
                pkgVersion: 'GET',
                fixedVersion: 'Set X-Content-Type-Options: nosniff.',
                pkgPath: 'https://app.example.test/login',
                layer: {
                    scanner: 'zap',
                    confidence: 'High',
                    wascId: '15',
                    evidence: 'X-Content-Type-Options',
                },
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
            pkgVersion: 'unknown',
            pkgPath: 'https://info.example.test',
        }));
    });

    it('rejects empty or invalid ZAP reports', () => {
        expect(() => service.parse(null)).toThrow(BadRequestException);
        expect(() => service.parse({ site: [] })).toThrow(BadRequestException);
    });
});
