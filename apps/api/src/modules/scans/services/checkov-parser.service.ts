import { BadRequestException, Injectable } from '@nestjs/common';
import { Severity } from '@prisma/client';
import { ParsedScanResult, ParsedVulnerability } from './trivy-parser.service';

type CheckovReport = {
    check_type?: string;
    checkov_version?: string;
    passed?: number;
    failed?: number;
    skipped?: number;
    parsing_errors?: number;
    resource_count?: number;
    summary?: {
        checkov_version?: string;
        parsing_errors?: number;
        resource_count?: number;
        passed?: number;
        failed?: number;
        skipped?: number;
    };
    results?: {
        failed_checks?: CheckovFailedCheck[];
    };
};

type CheckovFailedCheck = {
    check_id?: string;
    bc_check_id?: string;
    check_name?: string;
    description?: string;
    file_path?: string;
    file_abs_path?: string;
    repo_file_path?: string;
    file_line_range?: number[];
    resource?: string;
    guideline?: string;
    severity?: string;
};

@Injectable()
export class CheckovParserService {
    parse(rawResult: unknown): ParsedScanResult {
        if (!rawResult) {
            throw new BadRequestException('Empty Checkov scan result');
        }

        const reports = this.normalizeReports(rawResult);
        const originalFileName = this.getOriginalFileName(rawResult);
        const vulnerabilities = reports.flatMap((report) => this.parseFailedChecks(report, originalFileName));

        if (reports.length === 0 || (vulnerabilities.length === 0 && !this.hasValidCheckovShape(reports))) {
            throw new BadRequestException('Invalid Checkov JSON format');
        }

        const version = reports.find((report) => report.summary?.checkov_version || report.checkov_version);
        const artifactName = originalFileName || this.extractArtifactName(reports);

        return {
            trivyVersion: version ? `checkov-${version.summary?.checkov_version || version.checkov_version}` : 'checkov',
            schemaVersion: 'checkov-json',
            artifactName,
            artifactType: 'checkov',
            vulnerabilities,
        };
    }

    private normalizeReports(rawResult: unknown): CheckovReport[] {
        if (Array.isArray(rawResult)) {
            return rawResult.filter((item): item is CheckovReport => !!item && typeof item === 'object');
        }

        if (typeof rawResult === 'object') {
            return [rawResult as CheckovReport];
        }

        return [];
    }

    private hasValidCheckovShape(reports: CheckovReport[]): boolean {
        return reports.some((report) => (
            Array.isArray(report.results?.failed_checks)
            || !!report.summary
            || typeof report.checkov_version === 'string'
            || typeof report.passed === 'number'
            || typeof report.failed === 'number'
            || typeof report.parsing_errors === 'number'
        ));
    }

    private parseFailedChecks(report: CheckovReport, originalFileName?: string): ParsedVulnerability[] {
        const checkType = report.check_type || 'iac';
        const failedChecks = Array.isArray(report.results?.failed_checks)
            ? report.results.failed_checks
            : [];

        return failedChecks
            .filter((check) => check?.check_id)
            .map((check) => {
                const reference = check.guideline || (check.bc_check_id ? `https://www.checkov.io/5.Policy%20Index/all.html?query=${encodeURIComponent(check.bc_check_id)}` : undefined);
                const checkPath = check.file_path || check.repo_file_path || check.file_abs_path;
                const displayPath = this.displayPath(checkPath, originalFileName);
                const pkgPath = this.formatLocation(displayPath, check.file_line_range);

                return {
                    cveId: check.check_id as string,
                    title: check.check_name || check.check_id,
                    description: check.description || check.check_name,
                    severity: this.mapSeverity(check.severity),
                    references: reference ? [reference] : [],
                    cweIds: [],
                    pkgName: this.displayPath(check.resource, originalFileName) || displayPath || 'iac-resource',
                    pkgVersion: checkType,
                    fixedVersion: undefined,
                    pkgPath,
                    layer: {
                        scanner: 'checkov',
                        checkType,
                        bcCheckId: check.bc_check_id,
                    },
                };
            });
    }

    private formatLocation(filePath?: string, lineRange?: number[]): string | undefined {
        if (!filePath) return undefined;
        if (!Array.isArray(lineRange) || lineRange.length === 0) return filePath;
        const [start, end] = lineRange;
        return end && end !== start ? `${filePath}:${start}-${end}` : `${filePath}:${start}`;
    }

    private getOriginalFileName(rawResult: unknown): string | undefined {
        const evidence = Array.isArray(rawResult)
            ? (rawResult[0] as any)?.Metadata?.JascaScanEvidence
            : (rawResult as any)?.Metadata?.JascaScanEvidence;
        const originalFileName = evidence?.originalFileName;
        return typeof originalFileName === 'string' && originalFileName.trim()
            ? originalFileName.trim()
            : undefined;
    }

    private displayPath(value?: string, originalFileName?: string): string | undefined {
        if (!value) return undefined;
        const normalized = value.replace(/\\/g, '/');
        if (!originalFileName) return normalized;

        const marker = `/${originalFileName}`;
        const markerIndex = normalized.lastIndexOf(marker);
        if (markerIndex >= 0) {
            return this.trimDisplayPath(normalized.slice(markerIndex + 1));
        }

        return this.trimDisplayPath(normalized);
    }

    private trimDisplayPath(value: string): string {
        return value.replace(/[./]+$/g, '');
    }

    private extractArtifactName(reports: CheckovReport[]): string {
        const firstPath = reports
            .flatMap((report) => report.results?.failed_checks || [])
            .find((check) => check.file_path)?.file_path;

        return firstPath || 'checkov-scan';
    }

    private mapSeverity(severity?: string): Severity {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL':
                return 'CRITICAL';
            case 'HIGH':
                return 'HIGH';
            case 'MEDIUM':
                return 'MEDIUM';
            case 'LOW':
                return 'LOW';
            default:
                return 'UNKNOWN';
        }
    }
}
