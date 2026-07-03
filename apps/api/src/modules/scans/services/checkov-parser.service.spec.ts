import { BadRequestException } from '@nestjs/common';
import { CheckovParserService } from './checkov-parser.service';

describe('CheckovParserService', () => {
    const service = new CheckovParserService();

    it('maps failed Checkov checks to JASCA parsed vulnerabilities', () => {
        const parsed = service.parse({
            check_type: 'terraform',
            summary: {
                parsing_errors: 0,
                resource_count: 2,
                checkov_version: '3.2.0',
            },
            results: {
                failed_checks: [
                    {
                        check_id: 'CKV_AWS_20',
                        bc_check_id: 'BC_AWS_S3_13',
                        check_name: 'S3 Bucket has an ACL defined which allows public READ access.',
                        check_result: { result: 'FAILED' },
                        file_path: '/main.tf',
                        file_line_range: [12, 18],
                        resource: 'aws_s3_bucket.public',
                        guideline: 'https://docs.prismacloud.io/checkov/CKV_AWS_20',
                        severity: 'HIGH',
                    },
                ],
            },
        });

        expect(parsed.artifactType).toBe('checkov');
        expect(parsed.trivyVersion).toBe('checkov-3.2.0');
        expect(parsed.vulnerabilities).toEqual([
            expect.objectContaining({
                cveId: 'CKV_AWS_20',
                severity: 'HIGH',
                title: 'S3 Bucket has an ACL defined which allows public READ access.',
                pkgName: 'aws_s3_bucket.public',
                pkgVersion: 'terraform',
                pkgPath: '/main.tf:12-18',
                references: ['https://docs.prismacloud.io/checkov/CKV_AWS_20'],
            }),
        ]);
    });

    it('supports Checkov reports with multiple runner sections', () => {
        const parsed = service.parse([
            {
                check_type: 'kubernetes',
                results: {
                    failed_checks: [{ check_id: 'CKV_K8S_8', check_name: 'Liveness Probe Should be Configured', file_path: '/deployment.yaml' }],
                },
            },
            {
                check_type: 'dockerfile',
                results: {
                    failed_checks: [{ check_id: 'CKV_DOCKER_2', check_name: 'Healthcheck instructions should be added', file_path: '/Dockerfile' }],
                },
            },
        ]);

        expect(parsed.vulnerabilities.map((finding) => finding.cveId)).toEqual(['CKV_K8S_8', 'CKV_DOCKER_2']);
        expect(parsed.vulnerabilities[0].severity).toBe('UNKNOWN');
    });

    it('redacts server temporary upload paths from Checkov CLI results', () => {
        const parsed = service.parse({
            check_type: 'dockerfile',
            Metadata: {
                JascaScanEvidence: {
                    originalFileName: 'Dockerfile',
                },
            },
            results: {
                failed_checks: [
                    {
                        check_id: 'CKV_DOCKER_8',
                        check_name: 'Ensure the last USER is not root',
                        file_path: '/tmp/jasca-trivy-uploads/abc-123/Dockerfile',
                        file_line_range: [2, 2],
                        resource: '/tmp/jasca-trivy-uploads/abc-123/Dockerfile.USER',
                    },
                ],
            },
        });

        expect(parsed.artifactName).toBe('Dockerfile');
        expect(parsed.vulnerabilities[0].pkgName).toBe('Dockerfile.USER');
        expect(parsed.vulnerabilities[0].pkgPath).toBe('Dockerfile:2');
    });

    it('does not leave trailing separators on Dockerfile root resources', () => {
        const parsed = service.parse({
            check_type: 'dockerfile',
            Metadata: {
                JascaScanEvidence: {
                    originalFileName: 'Dockerfile',
                },
            },
            results: {
                failed_checks: [
                    {
                        check_id: 'CKV_DOCKER_2',
                        check_name: 'Ensure HEALTHCHECK exists',
                        file_path: '/tmp/jasca-trivy-uploads/abc-123/Dockerfile',
                        file_line_range: [1, 1],
                        resource: '/tmp/jasca-trivy-uploads/abc-123/Dockerfile.',
                    },
                ],
            },
        });

        expect(parsed.vulnerabilities[0].pkgName).toBe('Dockerfile');
        expect(parsed.vulnerabilities[0].pkgPath).toBe('Dockerfile:1');
    });

    it('accepts Checkov summary-only JSON when a framework has no findings', () => {
        const parsed = service.parse({
            passed: 0,
            failed: 0,
            skipped: 0,
            parsing_errors: 0,
            resource_count: 0,
            checkov_version: '3.3.6',
            Metadata: {
                JascaScanEvidence: {
                    originalFileName: 'playbook.yml',
                },
            },
        });

        expect(parsed.artifactName).toBe('playbook.yml');
        expect(parsed.trivyVersion).toBe('checkov-3.3.6');
        expect(parsed.vulnerabilities).toEqual([]);
    });

    it('rejects empty or invalid Checkov reports', () => {
        expect(() => service.parse(null)).toThrow(BadRequestException);
        expect(() => service.parse({ results: {} })).toThrow(BadRequestException);
    });
});
