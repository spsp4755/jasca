'use client';

import { useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
    ArrowLeft,
    Calendar,
    Package,
    AlertCircle,
    CheckCircle,
    ChevronRight,
    Loader2,
    RefreshCw,
    Scale,
    Shield,
    AlertTriangle,
    Info,
    HelpCircle,
    ChevronDown,
    ChevronUp,
    Download,
    FileJson,
} from 'lucide-react';
import { useScan, useLicensesByScan, useScanBestFixes, LicenseClassification } from '@/lib/api-hooks';
import { AiButton, AiResultPanel } from '@/components/ai';
import { useAiExecution } from '@/hooks/use-ai-execution';
import { downloadWithAuth } from '@/lib/api/fetch-utils';
import { ClustaraDeliveryPanel } from '@/components/clustara-delivery-panel';

// License classification config
const CLASSIFICATION_CONFIG: Record<LicenseClassification, { label: string; color: string; bgColor: string }> = {
    FORBIDDEN: { label: '금지', color: '#dc2626', bgColor: 'bg-red-100 dark:bg-red-900/30' },
    RESTRICTED: { label: '제한적', color: '#ea580c', bgColor: 'bg-orange-100 dark:bg-orange-900/30' },
    RECIPROCAL: { label: '상호적', color: '#ca8a04', bgColor: 'bg-yellow-100 dark:bg-yellow-900/30' },
    NOTICE: { label: '고지', color: '#2563eb', bgColor: 'bg-blue-100 dark:bg-blue-900/30' },
    PERMISSIVE: { label: '허용', color: '#16a34a', bgColor: 'bg-green-100 dark:bg-green-900/30' },
    UNENCUMBERED: { label: '무제한', color: '#059669', bgColor: 'bg-emerald-100 dark:bg-emerald-900/30' },
    UNKNOWN: { label: '미확인', color: '#64748b', bgColor: 'bg-slate-100 dark:bg-slate-700' },
};


function getSeverityColor(severity: string) {
    switch (severity?.toUpperCase()) {
        case 'CRITICAL':
            return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 border-red-200 dark:border-red-800';
        case 'HIGH':
            return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 border-orange-200 dark:border-orange-800';
        case 'MEDIUM':
            return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800';
        case 'LOW':
            return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 border-blue-200 dark:border-blue-800';
        default:
            return 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-600';
    }
}

function getSeverityBgOnly(severity: string) {
    switch (severity?.toUpperCase()) {
        case 'CRITICAL': return 'bg-red-500';
        case 'HIGH': return 'bg-orange-500';
        case 'MEDIUM': return 'bg-yellow-500';
        case 'LOW': return 'bg-blue-500';
        default: return 'bg-slate-400';
    }
}

function formatDate(dateString?: string | null) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return '-';
    return date.toLocaleDateString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatBytes(bytes?: number | null) {
    if (!bytes || bytes < 0) return '-';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }
    return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatDuration(ms?: number | null) {
    if (!ms || ms < 0) return '-';
    if (ms < 1000) return `${ms}ms`;
    const seconds = Math.round(ms / 1000);
    if (seconds < 60) return `${seconds}초`;
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    return `${minutes}분 ${rest}초`;
}

export default function ScanDetailPage() {
    const params = useParams();
    const id = params?.id as string;
    const { data: scan, isLoading, error, refetch } = useScan(id);
    const { data: licenses, isLoading: licensesLoading } = useLicensesByScan(id);
    const { data: bestFixes } = useScanBestFixes(id);
    const [showLicenses, setShowLicenses] = useState(false);
    const [downloading, setDownloading] = useState<string | null>(null);

    // AI analysis (feature: scan detail AI analysis)
    const {
        execute: executeAiAnalysis,
        isLoading: aiLoading,
        result: aiResult,
        previousResults: aiPreviousResults,
        estimateTokens,
        cancel: cancelAi,
        progress: aiProgress,
        isPanelOpen: aiPanelOpen,
        openPanel: openAiPanel,
        closePanel: closeAiPanel,
    } = useAiExecution('scan.analysis', { entityId: id });

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            </div>
        );
    }

    if (error || !scan) {
        return (
            <div className="flex flex-col items-center justify-center h-64 space-y-4">
                <AlertCircle className="h-12 w-12 text-red-500" />
                <p className="text-slate-600 dark:text-slate-400">스캔 결과를 불러오는데 실패했습니다.</p>
                <button
                    onClick={() => refetch()}
                    className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                    <RefreshCw className="h-4 w-4" />
                    다시 시도
                </button>
            </div>
        );
    }

    const summary = (scan as any).summary || {};
    const vulnerabilities = (scan as any).vulnerabilities || [];
    const targetName = (scan as any).targetName || (scan as any).imageRef || (scan as any).artifactName || 'Unknown';
    const scanLocation = (scan as any).scanLocation || (scan as any).artifactName;
    const evidence = (scan as any).scanEvidence;
    const evidenceSummary = evidence?.resultSummary;
    const sourceType = (scan as any).sourceType || '';
    const isCheckovScan = sourceType === 'CHECKOV_JSON' || evidence?.scanner === 'checkov' || (scan as any).artifactType === 'checkov';
    const isZapScan = sourceType === 'ZAP_JSON' || evidence?.scanner === 'zap' || (scan as any).artifactType === 'zap';
    const isSarifScan = sourceType === 'SARIF';
    const scannerLabel = isZapScan ? 'ZAP' : isCheckovScan ? 'Checkov' : isSarifScan ? (evidence?.scanner ? String(evidence.scanner).toUpperCase() : 'SAST (SARIF)') : 'Trivy';
    const evidenceCommands = [
        ...(Array.isArray(evidence?.commands) ? evidence.commands : []),
        ...(evidence?.command ? [{ phase: `${scannerLabel.toLowerCase()}-scan`, command: evidence.command }] : []),
    ];
    const formatOptionValue = (value: unknown) => {
        if (Array.isArray(value)) return value.length ? value.join(', ') : '-';
        if (typeof value === 'boolean') return value ? 'true' : 'false';
        if (value === undefined || value === null || value === '') return '-';
        return String(value);
    };
    const evidenceStats = isZapScan
        ? [
            ['Alerts', vulnerabilities.length],
            ['Mode', evidence?.scanMode || '-'],
            ['ZAP Version', evidence?.zapVersion || (scan as any).trivyVersion || '-'],
            ['Target', evidence?.targetUrl || targetName],
        ]
        : isCheckovScan
        ? [
            ['Failed Checks', vulnerabilities.length],
            ['Frameworks', formatOptionValue(evidence?.options?.frameworks)],
            ['Input Kind', evidence?.inputKind || '-'],
            ['Archive', evidence?.archiveType || '-'],
        ]
        : isSarifScan
        ? [
            ['Findings', vulnerabilities.length],
            ['Profile', evidence?.options?.profile || '-'],
            ['Languages', formatOptionValue(evidence?.options?.languages)],
            ['Custom Rules', evidence?.options?.customRulesApplied ? 'applied' : '-'],
            ['Input Kind', evidence?.inputKind || '-'],
            ['Archive', evidence?.archiveType || '-'],
        ]
        : [
            ['Results', evidenceSummary?.resultCount ?? 0],
            ['Packages', evidenceSummary?.packages ?? 0],
            ['Vulns', evidenceSummary?.vulnerabilities ?? 0],
            ['Licenses', evidenceSummary?.licenses ?? 0],
            ['Misconfig', evidenceSummary?.misconfigurations ?? 0],
            ['Secrets', evidenceSummary?.secrets ?? 0],
        ];

    const hasVulnerabilities = vulnerabilities.length > 0;
    const hasLicenses = Array.isArray(licenses) && licenses.length > 0;

    // Build a compact context for AI analysis (cap vuln list to keep tokens sane).
    const buildAiContext = () => ({
        screen: 'scanDetail',
        target: targetName,
        project: (scan as any).project?.name,
        summary,
        topVulnerabilities: vulnerabilities.slice(0, 40).map((v: any) => ({
            cveId: v.vulnerability?.cveId,
            severity: v.vulnerability?.severity,
            pkgName: v.pkgName,
            installedVersion: v.installedVersion,
            fixedVersion: v.fixedVersion,
            title: v.vulnerability?.title,
        })),
        licenseIssues: (licenses || [])
            .filter((l: any) => ['FORBIDDEN', 'RESTRICTED', 'RECIPROCAL'].includes(l.classification))
            .slice(0, 40)
            .map((l: any) => ({ name: l.name, spdxId: l.spdxId, classification: l.classification, packages: l.packageCount })),
    });

    const handleAiAnalyze = () => {
        if (aiResult) {
            openAiPanel();
            return;
        }

        executeAiAnalysis(buildAiContext());
    };

    const aiEstimatedTokens = estimateTokens(buildAiContext());

    const handleDownload = async (type: 'vulnerabilities' | 'licenses', format: 'csv' | 'json') => {
        const key = `${type}-${format}`;
        setDownloading(key);
        try {
            await downloadWithAuth(
                `/api/scans/${id}/export/${type}?format=${format}`,
                `scan-${id}-${type}.${format}`,
            );
        } catch (e) {
            console.error('Download failed', e);
            alert('다운로드에 실패했습니다.');
        } finally {
            setDownloading(null);
        }
    };

    const handleDownloadRaw = async () => {
        setDownloading('raw');
        try {
            await downloadWithAuth(`/api/scans/${id}/result/raw`, `${id}.json`);
        } catch (e) {
            console.error('Raw download failed', e);
            alert('원본 결과 다운로드에 실패했습니다.');
        } finally {
            setDownloading(null);
        }
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center gap-4">
                <Link
                    href="/dashboard/scans"
                    className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                >
                    <ArrowLeft className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                </Link>
                <div className="flex-1">
                    <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
                        스캔 상세 정보
                    </h2>
                    <p className="text-slate-600 dark:text-slate-400 mt-1">
                        {targetName}
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    {/* AI analysis */}
                    <AiButton
                        action="scan.analysis"
                        variant="primary"
                        size="md"
                        estimatedTokens={aiEstimatedTokens}
                        loading={aiLoading}
                        onExecute={handleAiAnalyze}
                        onCancel={cancelAi}
                    />

                    {/* Download dropdown */}
                    <div className="relative group">
                        <button className="flex items-center gap-1.5 px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">
                            <Download className="h-4 w-4" />
                            다운로드
                            <ChevronDown className="h-4 w-4" />
                        </button>
                        <div className="absolute right-0 top-full mt-1 w-56 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-20 py-1">
                            <p className="px-3 py-1 text-[11px] font-semibold text-slate-400 uppercase">취약점 목록</p>
                            <button
                                disabled={!hasVulnerabilities || downloading !== null}
                                onClick={() => handleDownload('vulnerabilities', 'csv')}
                                className="w-full px-3 py-2 text-xs text-left hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                📄 CSV 다운로드
                            </button>
                            <button
                                disabled={!hasVulnerabilities || downloading !== null}
                                onClick={() => handleDownload('vulnerabilities', 'json')}
                                className="w-full px-3 py-2 text-xs text-left hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                📋 JSON 다운로드
                            </button>
                            <p className="px-3 py-1 mt-1 text-[11px] font-semibold text-slate-400 uppercase">패키지 라이선스</p>
                            <button
                                disabled={!hasLicenses || downloading !== null}
                                onClick={() => handleDownload('licenses', 'csv')}
                                className="w-full px-3 py-2 text-xs text-left hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                📄 CSV 다운로드
                            </button>
                            <button
                                disabled={!hasLicenses || downloading !== null}
                                onClick={() => handleDownload('licenses', 'json')}
                                className="w-full px-3 py-2 text-xs text-left hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                📋 JSON 다운로드
                            </button>
                            <div className="my-1 border-t border-slate-200 dark:border-slate-700" />
                            <button
                                disabled={downloading !== null}
                                onClick={handleDownloadRaw}
                                className="w-full flex items-center gap-1.5 px-3 py-2 text-xs text-left hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                <FileJson className="h-3.5 w-3.5" />
                                원본 결과(JSON) 다운로드
                            </button>
                        </div>
                    </div>

                    <button
                        onClick={() => refetch()}
                        className="flex items-center gap-2 px-3 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                    >
                        <RefreshCw className="h-4 w-4" />
                        새로고침
                    </button>
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div className="bg-white dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-500 dark:text-slate-400">Critical</span>
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                    </div>
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400 mt-2">
                        {summary.critical || 0}
                    </p>
                </div>
                <div className="bg-white dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-500 dark:text-slate-400">High</span>
                        <div className="w-3 h-3 rounded-full bg-orange-500"></div>
                    </div>
                    <p className="text-2xl font-bold text-orange-600 dark:text-orange-400 mt-2">
                        {summary.high || 0}
                    </p>
                </div>
                <div className="bg-white dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-500 dark:text-slate-400">Medium</span>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                    </div>
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400 mt-2">
                        {summary.medium || 0}
                    </p>
                </div>
                <div className="bg-white dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-500 dark:text-slate-400">Low</span>
                        <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                    </div>
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-2">
                        {summary.low || 0}
                    </p>
                </div>
                <div className="bg-white dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-500 dark:text-slate-400">Total</span>
                    </div>
                    <p className="text-2xl font-bold text-slate-900 dark:text-white mt-2">
                        {summary.totalVulns || vulnerabilities.length || 0}
                    </p>
                </div>
            </div>

            {/* Scan Info */}
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
                    스캔 정보
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
                    <div>
                        <span className="text-sm text-slate-500 dark:text-slate-400">프로젝트</span>
                        <p className="font-medium text-slate-900 dark:text-white">
                            {(scan as any).project?.name || '-'}
                        </p>
                    </div>
                    <div>
                        <span className="text-sm text-slate-500 dark:text-slate-400">대상</span>
                        <p className="font-medium text-slate-900 dark:text-white truncate" title={targetName}>
                            {targetName}
                        </p>
                    </div>
                    <div>
                        <span className="text-sm text-slate-500 dark:text-slate-400">검사 위치</span>
                        <p className="font-medium text-slate-900 dark:text-white truncate" title={scanLocation || undefined}>
                            {(() => {
                                const path = scanLocation;
                                if (!path || path === '.') {
                                    return (scan as any).artifactType === 'filesystem' 
                                        ? '현재 디렉토리 (.)'
                                        : '-';
                                }
                                return path;
                            })()}
                        </p>
                    </div>
                    <div>
                        <span className="text-sm text-slate-500 dark:text-slate-400">태그</span>
                        <p className="font-medium text-slate-900 dark:text-white">
                            {(scan as any).tag || '-'}
                        </p>
                    </div>
                    <div>
                        <span className="text-sm text-slate-500 dark:text-slate-400">스캔 일시</span>
                        <p className="font-medium text-slate-900 dark:text-white">
                            {formatDate((scan as any).createdAt)}
                        </p>
                    </div>
                </div>
                {/* Source Information */}
                <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
                    <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">업로드 출처</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div>
                            <span className="text-sm text-slate-500 dark:text-slate-400">소스 타입</span>
                            <p className="font-medium text-slate-900 dark:text-white">
                                <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${(scan as any).sourceType === 'MANUAL'
                                        ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'
                                        : (scan as any).sourceType?.startsWith('CI_')
                                            ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                                            : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                                    }`}>
                                    {(scan as any).sourceType || 'UNKNOWN'}
                                </span>
                            </p>
                        </div>
                        <div>
                            <span className="text-sm text-slate-500 dark:text-slate-400">업로더 IP</span>
                            <p className="font-mono text-sm text-slate-900 dark:text-white">
                                {(scan as any).uploaderIp || '-'}
                            </p>
                        </div>
                        <div>
                            <span className="text-sm text-slate-500 dark:text-slate-400">User-Agent</span>
                            <p className="font-medium text-slate-900 dark:text-white text-sm truncate" title={(scan as any).userAgent}>
                                {(scan as any).userAgent
                                    ? ((scan as any).userAgent.length > 40
                                        ? (scan as any).userAgent.substring(0, 40) + '...'
                                        : (scan as any).userAgent)
                                    : '-'}
                            </p>
                        </div>
                        <div>
                            <span className="text-sm text-slate-500 dark:text-slate-400">CI 파이프라인</span>
                            <p className="font-medium text-slate-900 dark:text-white">
                                {(scan as any).ciPipeline || '-'}
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {!isCheckovScan && !isZapScan && !isSarifScan ? <ClustaraDeliveryPanel scan={scan} /> : null}

            {/* Scanner Execution Evidence */}
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
                <div className="flex items-start justify-between gap-4 mb-4">
                    <div>
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                            <Shield className="h-5 w-5 text-blue-500" />
                            {scannerLabel} 검사 검증 정보
                        </h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                            {isZapScan
                                ? 'ZAP 결과는 웹 URL에서 수집된 alert 수를 기준으로 판단합니다.'
                                : isCheckovScan
                                ? '정책 실패가 0건이어도 아래 값이 있으면 Checkov 실행과 결과 파싱이 완료된 것입니다.'
                                : isSarifScan
                                ? 'SARIF 결과는 도구 정보(tool.driver)를 기준으로 스캐너를 판별합니다. 업로드된 SARIF는 JASCA가 직접 실행한 검사가 아닐 수 있습니다.'
                                : '취약점이 0건이어도 아래 값이 있으면 Trivy 실행과 결과 파싱이 완료된 것입니다.'}
                        </p>
                    </div>
                    <span className={`inline-flex px-3 py-1 rounded-full text-xs font-medium ${
                        evidence?.completed
                            ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                            : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                    }`}>
                        {evidence?.completed ? '검사 완료 증거 있음' : '직접 검사 증거 없음'}
                    </span>
                </div>

                {evidence ? (
                    <div className="space-y-5">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div>
                                <span className="text-sm text-slate-500 dark:text-slate-400">업로드 파일</span>
                                <p className="font-medium text-slate-900 dark:text-white truncate" title={evidence.originalFileName}>
                                    {evidence.originalFileName || '-'}
                                </p>
                            </div>
                            <div>
                                <span className="text-sm text-slate-500 dark:text-slate-400">{isZapScan ? '대상 URL' : isCheckovScan ? '입력 유형' : '파일 크기'}</span>
                                <p className="font-medium text-slate-900 dark:text-white">
                                    {isZapScan ? (evidence.targetUrl || targetName) : isCheckovScan ? (evidence.inputKind || '-') : formatBytes(evidence.fileSizeBytes)}
                                </p>
                            </div>
                            <div>
                                <span className="text-sm text-slate-500 dark:text-slate-400">{isZapScan ? 'ZAP 모드' : isCheckovScan ? 'Checkov Framework' : '검사 모드'}</span>
                                <p className="font-medium text-slate-900 dark:text-white">
                                    {isZapScan
                                        ? evidence.scanMode || '-'
                                        : isCheckovScan
                                        ? formatOptionValue(evidence.options?.frameworks)
                                        : `${evidence.scanMode || '-'}${evidence.archiveType ? ` / ${evidence.archiveType}` : ''}`}
                                </p>
                            </div>
                            <div>
                                <span className="text-sm text-slate-500 dark:text-slate-400">소요 시간</span>
                                <p className="font-medium text-slate-900 dark:text-white">
                                    {formatDuration(evidence.durationMs)}
                                </p>
                            </div>
                        </div>

                        <div className={`grid grid-cols-2 md:grid-cols-3 ${isCheckovScan || isZapScan ? 'lg:grid-cols-4' : 'lg:grid-cols-6'} gap-3`}>
                            {evidenceStats.map(([label, value]) => (
                                <div key={label} className="rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700 p-3">
                                    <span className="text-xs text-slate-500 dark:text-slate-400">{label}</span>
                                    <p className="text-lg font-semibold text-slate-900 dark:text-white">{value}</p>
                                </div>
                            ))}
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
                                <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-3">실행 옵션</h4>
                                <div className="space-y-2 text-sm">
                                    {isZapScan ? (
                                        <>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Mode</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{evidence.scanMode || '-'}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Target URL</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right break-all">{evidence.targetUrl || targetName}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Max Duration</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.maxScanDurationMinutes)} min</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Active Allowed</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.allowActiveScan)}</span>
                                            </div>
                                        </>
                                    ) : isCheckovScan ? (
                                        <>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Framework</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.frameworks)}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Run Checks</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.checks)}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Skip Checks</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.skipChecks)}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Internal Modules</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">
                                                    downloadExternalModules={formatOptionValue(evidence.options?.downloadExternalModules)}
                                                </span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Timeout</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.timeout)}</span>
                                            </div>
                                        </>
                                    ) : isSarifScan ? (
                                        <>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Tool</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{evidence.scanner || '-'}{evidence.toolVersion ? ` ${evidence.toolVersion}` : ''}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Profile</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{evidence.options?.profile || '-'}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Languages</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{formatOptionValue(evidence.options?.languages)}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Custom Rules</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{evidence.options?.customRulesApplied ? 'applied' : '-'}</span>
                                            </div>
                                        </>
                                    ) : (
                                        <>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Scanners</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{evidence.options?.scanners?.join(', ') || '-'}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Severity</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">{evidence.options?.severities?.join(', ') || '-'}</span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Offline / DB Update</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">
                                                    offline={String(evidence.options?.offlineScan)} / skipDb={String(evidence.options?.skipDbUpdate)}
                                                </span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Analysis Strategy</span>
                                                <span className="font-medium text-slate-900 dark:text-white text-right">
                                                    {evidence.options?.analysisStrategy || '-'}
                                                </span>
                                            </div>
                                            <div className="flex justify-between gap-4">
                                                <span className="text-slate-500">Cache Dir</span>
                                                <span className="font-mono text-xs text-slate-900 dark:text-white text-right break-all">{evidence.cacheDir || '-'}</span>
                                            </div>
                                            {(evidence.options?.rpmOsFamily || evidence.options?.rpmOsVersion) && (
                                                <div className="flex justify-between gap-4">
                                                    <span className="text-slate-500">RPM OS</span>
                                                    <span className="font-medium text-slate-900 dark:text-white text-right">
                                                        {evidence.options?.rpmOsFamily || '-'} {evidence.options?.rpmOsVersion || ''}
                                                    </span>
                                                </div>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>

                            <div className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
                                <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-3">{isCheckovScan ? 'Checkov 분석 대상' : '검사 대상'}</h4>
                                <div className="space-y-2 max-h-40 overflow-auto">
                                    {isCheckovScan ? (
                                        <div className="text-sm">
                                            <p className="font-medium text-slate-900 dark:text-white break-all">{scanLocation || evidence.originalFileName || targetName}</p>
                                            <p className="text-xs text-slate-500 mt-1">
                                                {evidence.inputKind || '-'}{evidence.archiveType ? ` / ${evidence.archiveType}` : ''} · failed checks {vulnerabilities.length}
                                            </p>
                                            <p className="text-xs text-slate-500 mt-2">
                                                Checkov 결과는 패키지 수가 아니라 IaC/CI/Dockerfile 정책 실패 수를 기준으로 판단합니다.
                                            </p>
                                        </div>
                                    ) : (evidenceSummary?.targets || []).length > 0 ? (
                                        evidenceSummary.targets.map((target: any, index: number) => (
                                            <div key={`${target.target}-${index}`} className="text-sm border-b border-slate-100 dark:border-slate-700 last:border-0 pb-2 last:pb-0">
                                                <p className="font-medium text-slate-900 dark:text-white break-all">{target.target || 'unknown'}</p>
                                                <p className="text-xs text-slate-500">
                                                    {target.class || '-'} / {target.type || '-'} · vulns {target.vulnerabilities || 0} · packages {target.packages || 0}
                                                </p>
                                            </div>
                                        ))
                                    ) : isSarifScan ? (
                                        <div className="text-sm">
                                            <p className="font-medium text-slate-900 dark:text-white break-all">{evidence.originalFileName || targetName}</p>
                                            <p className="text-xs text-slate-500 mt-1">
                                                {evidence.inputKind || '-'}{evidence.archiveType ? ` / ${evidence.archiveType}` : ''} · findings {vulnerabilities.length}
                                            </p>
                                        </div>
                                    ) : (
                                        <p className="text-sm text-amber-600 dark:text-amber-300">
                                            Trivy Results가 0개입니다. 이 경우 검사 대상 형식, 스캔 모드, DB 설정을 다시 확인해야 합니다.
                                        </p>
                                    )}
                                </div>
                            </div>
                        </div>

                        <details className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
                            <summary className="cursor-pointer text-sm font-semibold text-slate-800 dark:text-slate-200">
                                실행 명령 확인
                            </summary>
                            <div className="mt-3 space-y-2">
                                {evidenceCommands.length > 0 ? evidenceCommands.map((command: any, index: number) => (
                                    <div key={`${command.phase}-${index}`}>
                                        <p className="text-xs text-slate-500 mb-1">{command.phase}</p>
                                        <code className="block text-xs bg-slate-100 dark:bg-slate-900 text-slate-800 dark:text-slate-200 rounded p-2 overflow-x-auto">
                                            {command.command}
                                        </code>
                                    </div>
                                )) : (
                                    <p className="text-sm text-slate-500 dark:text-slate-400">
                                        저장된 실행 명령이 없습니다.
                                    </p>
                                )}
                            </div>
                        </details>
                    </div>
                ) : (
                    <div className="flex items-start gap-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-4">
                        <Info className="h-5 w-5 text-amber-500 mt-0.5" />
                        <div>
                            <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
                                이 결과에는 JASCA 직접 검사 증거가 없습니다.
                            </p>
                            <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                                기존 JSON 업로드 결과이거나, 검증 정보가 추가되기 전 버전에서 생성된 스캔일 수 있습니다.
                            </p>
                        </div>
                    </div>
                )}
            </div>

            {/* Best Fix Suggestions */}
            {bestFixes && (bestFixes.packageFixes.length > 0 || bestFixes.codeFixes.length > 0) && (
                <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
                    <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Best Fix 제안</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                            공통 근원으로 묶었을 때 한 번의 조치로 여러 건이 해결되는 항목입니다.
                        </p>
                    </div>
                    <div className="p-6 space-y-3">
                        {bestFixes.packageFixes.slice(0, 5).map((fix) => (
                            <div key={`pkg-${fix.pkgName}`} className="flex items-start justify-between gap-4 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
                                <div className="min-w-0">
                                    <p className="font-medium text-slate-900 dark:text-white truncate">
                                        <span className="text-emerald-600 dark:text-emerald-400">패키지 업그레이드</span>
                                        <span className="mx-2 text-slate-300 dark:text-slate-600">|</span>
                                        {fix.pkgName} <span className="text-slate-400">{fix.currentVersion}</span> → <span className="font-semibold">{fix.recommendedVersion}</span>
                                    </p>
                                    <p className="text-xs text-slate-500 mt-1 truncate">{fix.cveIds.join(', ')}</p>
                                </div>
                                <span className="shrink-0 px-3 py-1 rounded-full text-sm font-bold bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">
                                    {fix.resolves}건 해결
                                </span>
                            </div>
                        ))}
                        {bestFixes.codeFixes.slice(0, 5).map((fix) => (
                            <div key={`code-${fix.ruleId}-${fix.file}`} className="flex items-start justify-between gap-4 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
                                <div className="min-w-0">
                                    <p className="font-medium text-slate-900 dark:text-white truncate">
                                        <span className="text-violet-600 dark:text-violet-400">코드 패턴 수정</span>
                                        <span className="mx-2 text-slate-300 dark:text-slate-600">|</span>
                                        {fix.file}
                                    </p>
                                    <p className="text-xs text-slate-500 mt-1 truncate">
                                        {fix.title || fix.ruleId} · {fix.locations.join(', ')}
                                    </p>
                                </div>
                                <span className="shrink-0 px-3 py-1 rounded-full text-sm font-bold bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300">
                                    {fix.resolves}건 해결
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Vulnerabilities List */}
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
                <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                        취약점 목록 ({vulnerabilities.length}개)
                    </h3>
                </div>

                {vulnerabilities.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                        <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
                        <p className="text-slate-600 dark:text-slate-400">
                            취약점이 발견되지 않았습니다.
                        </p>
                    </div>
                ) : (
                    <div className="divide-y divide-slate-200 dark:divide-slate-700">
                        {vulnerabilities.map((vuln: any, index: number) => (
                            <div key={vuln.id || index} className="px-6 py-4 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                                <div className="flex items-start gap-4">
                                    <span className={`px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(vuln.vulnerability?.severity || 'UNKNOWN')}`}>
                                        {vuln.vulnerability?.severity || 'UNKNOWN'}
                                    </span>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2">
                                            <span className="font-mono text-sm font-semibold text-blue-600 dark:text-blue-400">
                                                {vuln.vulnerability?.cveId || 'N/A'}
                                            </span>
                                            {vuln.vulnerability?.cvssV3Score && (
                                                <span className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">
                                                    CVSS: {vuln.vulnerability.cvssV3Score}
                                                </span>
                                            )}
                                        </div>
                                        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1 line-clamp-2">
                                            {vuln.vulnerability?.title || vuln.vulnerability?.description || '-'}
                                        </p>
                                        <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-slate-500">
                                            <span className="flex items-center gap-1">
                                                <Package className="h-3 w-3" />
                                                {isZapScan
                                                    ? `URL: ${vuln.pkgName || '-'}`
                                                    : isSarifScan
                                                        ? `${vuln.pkgName} (${vuln.pkgVersion || vuln.installedVersion || '-'})`
                                                        : `${vuln.pkgName}@${vuln.pkgVersion || vuln.installedVersion || '-'}`}
                                            </span>
                                            {isZapScan && (
                                                <span>Method: {vuln.installedVersion || vuln.pkgVersion || '-'}</span>
                                            )}
                                            {vuln.fixedVersion && (
                                                <span className="text-green-600 dark:text-green-400">
                                                    {isZapScan ? `Solution: ${vuln.fixedVersion}` : `Fixed: ${vuln.fixedVersion}`}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* License Section */}
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
                <button
                    onClick={() => setShowLicenses(!showLicenses)}
                    className="w-full px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                >
                    <div className="flex items-center gap-3">
                        <Scale className="h-5 w-5 text-purple-500" />
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                            패키지 라이선스 ({licenses?.length || 0}개)
                        </h3>
                        {licenses && licenses.some(l => l.classification === 'FORBIDDEN' || l.classification === 'RESTRICTED') && (
                            <span className="px-2 py-0.5 text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-full">
                                주의 필요
                            </span>
                        )}
                    </div>
                    {showLicenses ? (
                        <ChevronUp className="h-5 w-5 text-slate-400" />
                    ) : (
                        <ChevronDown className="h-5 w-5 text-slate-400" />
                    )}
                </button>

                {showLicenses && (
                    <div className="p-6">
                        {licensesLoading ? (
                            <div className="flex items-center justify-center py-8">
                                <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
                            </div>
                        ) : licenses && licenses.length > 0 ? (
                            <div className="space-y-3">
                                {licenses.map((license, index) => {
                                    const config = CLASSIFICATION_CONFIG[license.classification];
                                    return (
                                        <div
                                            key={`${license.spdxId}-${index}`}
                                            className="flex items-center justify-between p-3 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                                        >
                                            <div className="flex items-center gap-3">
                                                <span
                                                    className="px-2 py-1 text-xs font-medium rounded-full"
                                                    style={{
                                                        backgroundColor: `${config.color}20`,
                                                        color: config.color,
                                                    }}
                                                >
                                                    {config.label}
                                                </span>
                                                <div>
                                                    <p className="font-medium text-slate-900 dark:text-white">
                                                        {license.name}
                                                    </p>
                                                    <p className="text-xs text-slate-500">
                                                        SPDX: {license.spdxId}
                                                    </p>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <span className="text-sm text-slate-500">
                                                    {license.packageCount}개 패키지
                                                </span>
                                                <Package className="h-4 w-4 text-slate-400" />
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center py-8 text-center">
                                <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
                                <p className="text-slate-600 dark:text-slate-400">
                                    라이선스 정보가 없습니다.
                                </p>
                                <p className="text-xs text-slate-500 mt-1">
                                    스캔 결과에 패키지 라이선스 정보가 포함되지 않았습니다.
                                </p>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* AI Analysis Result Panel */}
            <AiResultPanel
                isOpen={aiPanelOpen}
                onClose={closeAiPanel}
                result={aiResult}
                previousResults={aiPreviousResults}
                loading={aiLoading}
                loadingProgress={aiProgress}
                action="scan.analysis"
            />
        </div>
    );
}
