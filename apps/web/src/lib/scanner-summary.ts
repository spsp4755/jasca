import type { Scan } from './api-hooks';

export type SecurityScanner = 'trivy' | 'checkov' | 'zap' | 'sarif';

export const SCANNER_META: Record<SecurityScanner, {
    label: string;
    shortLabel: string;
    resultLabel: string;
    description: string;
    accentClass: string;
    badgeClass: string;
}> = {
    trivy: {
        label: 'Trivy',
        shortLabel: '취약점',
        resultLabel: '취약점',
        description: '패키지 취약점, 라이선스, Secret, Misconfig 결과',
        accentClass: 'bg-blue-500',
        badgeClass: 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800',
    },
    checkov: {
        label: 'Checkov',
        shortLabel: '정책 위반',
        resultLabel: '정책 위반',
        description: 'IaC, Dockerfile, Kubernetes, CI 설정 정책 실패',
        accentClass: 'bg-cyan-500',
        badgeClass: 'bg-cyan-100 text-cyan-700 border-cyan-200 dark:bg-cyan-900/30 dark:text-cyan-300 dark:border-cyan-800',
    },
    zap: {
        label: 'ZAP',
        shortLabel: '웹 알림',
        resultLabel: '웹 보안 알림',
        description: '웹 URL 기반 DAST alert',
        accentClass: 'bg-amber-500',
        badgeClass: 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800',
    },
    sarif: {
        label: 'SAST (SARIF)',
        shortLabel: '코드 취약점',
        resultLabel: '코드 취약점',
        description: 'SARIF 업로드 기반 소스코드 정적분석 결과 (Semgrep, CodeQL 등)',
        accentClass: 'bg-violet-500',
        badgeClass: 'bg-violet-100 text-violet-700 border-violet-200 dark:bg-violet-900/30 dark:text-violet-300 dark:border-violet-800',
    },
};

export interface ScannerSummary {
    scanner: SecurityScanner;
    totalScans: number;
    completedScans: number;
    failedScans: number;
    runningScans: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    lastScanAt?: string;
}

export function getScanScanner(scan: Scan): SecurityScanner {
    const evidenceScanner = scan.scanEvidence?.scanner?.toLowerCase();
    const sourceType = scan.sourceType?.toUpperCase();
    const artifactType = scan.artifactType?.toLowerCase();

    if (evidenceScanner === 'zap' || sourceType === 'ZAP_JSON' || artifactType === 'zap') return 'zap';
    if (evidenceScanner === 'checkov' || sourceType === 'CHECKOV_JSON' || artifactType === 'checkov') return 'checkov';
    // TRIVY_SARIF stays attributed to Trivy; only the generic SARIF upload path maps here
    if (sourceType === 'SARIF') return 'sarif';
    return 'trivy';
}

export function getScanFindingTotal(scan: Scan) {
    return scan.summary?.total ?? (
        (scan.summary?.critical || 0) +
        (scan.summary?.high || 0) +
        (scan.summary?.medium || 0) +
        (scan.summary?.low || 0) +
        (scan.summary?.unknown || 0)
    );
}

export function scannerSummariesToList(scans: Scan[]): ScannerSummary[] {
    const summaries: Record<SecurityScanner, ScannerSummary> = {
        trivy: createEmptySummary('trivy'),
        checkov: createEmptySummary('checkov'),
        zap: createEmptySummary('zap'),
        sarif: createEmptySummary('sarif'),
    };

    for (const scan of scans) {
        const scanner = getScanScanner(scan);
        const summary = summaries[scanner];
        const scanTotal = getScanFindingTotal(scan);
        const status = scan.status?.toUpperCase();
        const scanDate = scan.completedAt || scan.startedAt || scan.createdAt;

        summary.totalScans += 1;
        summary.findings += scanTotal;
        summary.critical += scan.summary?.critical || 0;
        summary.high += scan.summary?.high || 0;
        summary.medium += scan.summary?.medium || 0;
        summary.low += scan.summary?.low || 0;
        summary.unknown += scan.summary?.unknown || 0;

        if (status === 'COMPLETED') summary.completedScans += 1;
        else if (status === 'FAILED') summary.failedScans += 1;
        else if (status === 'RUNNING') summary.runningScans += 1;

        if (scanDate && (!summary.lastScanAt || new Date(scanDate) > new Date(summary.lastScanAt))) {
            summary.lastScanAt = scanDate;
        }
    }

    return [summaries.trivy, summaries.checkov, summaries.zap, summaries.sarif];
}

function createEmptySummary(scanner: SecurityScanner): ScannerSummary {
    return {
        scanner,
        totalScans: 0,
        completedScans: 0,
        failedScans: 0,
        runningScans: 0,
        findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
    };
}
