'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
    ArrowLeft,
    ShieldCheck,
    ShieldX,
    AlertTriangle,
    CheckCircle,
    XCircle,
    Info,
    Loader2,
} from 'lucide-react';
import { usePolicyEvaluation, useScan } from '@/lib/api-hooks';

function getResultIcon(result: string) {
    switch (result) {
        case 'PASSED':
            return <CheckCircle className="h-5 w-5 text-green-500" />;
        case 'FAILED':
            return <XCircle className="h-5 w-5 text-red-500" />;
        case 'WARNING':
            return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
        default:
            return <Info className="h-5 w-5 text-slate-500" />;
    }
}

function getResultBadge(result: string) {
    const styles: Record<string, string> = {
        PASSED: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
        FAILED: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
        WARNING: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
    };
    const labels: Record<string, string> = {
        PASSED: '통과',
        FAILED: '실패',
        WARNING: '경고',
    };
    return (
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${styles[result] || ''}`}>
            {labels[result] || result}
        </span>
    );
}

export default function PolicyResultsPage() {
    const params = useParams();
    const scanId = params.id as string;
    const { data: scan, isLoading: scanLoading } = useScan(scanId);
    const {
        data: results,
        isLoading: evaluationLoading,
        error,
    } = usePolicyEvaluation(scan?.projectId, scanId);

    const policyResults = results
        ? [
            ...results.violations.map((violation) => ({ ...violation, result: 'FAILED' })),
            ...results.warnings.map((warning) => ({ ...warning, result: 'WARNING' })),
        ]
        : [];

    const failedCount = results?.violations.length || 0;
    const warningCount = results?.warnings.length || 0;
    const passedCount = results && results.allowed && warningCount === 0 ? 1 : 0;
    const deploymentAllowed = Boolean(results?.allowed);

    if (scanLoading || evaluationLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            </div>
        );
    }

    if (error || !results) {
        return (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-6 text-red-700 dark:text-red-300">
                정책 검사 결과를 불러오지 못했습니다.
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center gap-4">
                <Link
                    href={`/dashboard/scans/${scanId}`}
                    className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                >
                    <ArrowLeft className="h-5 w-5" />
                </Link>
                <div className="flex-1">
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">정책 검사 결과</h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1">
                        {scan?.targetName || scan?.imageRef || scanId}
                    </p>
                </div>
            </div>

            {/* Deployment Status */}
            <div className={`rounded-xl p-6 flex items-center gap-4 ${deploymentAllowed
                    ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800'
                    : 'bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800'
                }`}>
                <div className={`w-16 h-16 rounded-full flex items-center justify-center ${deploymentAllowed ? 'bg-green-100 dark:bg-green-900/30' : 'bg-red-100 dark:bg-red-900/30'
                    }`}>
                    {deploymentAllowed ? (
                        <ShieldCheck className="h-8 w-8 text-green-600 dark:text-green-400" />
                    ) : (
                        <ShieldX className="h-8 w-8 text-red-600 dark:text-red-400" />
                    )}
                </div>
                <div className="flex-1">
                    <h2 className={`text-xl font-bold ${deploymentAllowed ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'
                        }`}>
                        {deploymentAllowed ? '배포 허용' : '배포 차단'}
                    </h2>
                    <p className={deploymentAllowed ? 'text-green-600 dark:text-green-500' : 'text-red-600 dark:text-red-500'}>
                        {deploymentAllowed
                            ? (warningCount > 0 ? `${warningCount}개 경고가 있지만 차단 정책은 없습니다.` : '차단 정책을 모두 통과했습니다.')
                            : `${failedCount}개 정책 위반으로 배포가 차단되었습니다.`}
                    </p>
                </div>
                <Link
                    href="/admin/exceptions"
                    className="px-4 py-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors text-sm"
                >
                    예외 요청
                </Link>
            </div>

            {/* Summary */}
            <div className="grid grid-cols-3 gap-4">
                <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-green-200 dark:border-green-800 p-4 text-center">
                    <CheckCircle className="h-6 w-6 text-green-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-green-600 dark:text-green-400">{passedCount}</p>
                    <p className="text-sm text-slate-500">통과</p>
                </div>
                <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-red-200 dark:border-red-800 p-4 text-center">
                    <XCircle className="h-6 w-6 text-red-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400">{failedCount}</p>
                    <p className="text-sm text-slate-500">실패</p>
                </div>
                <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-yellow-200 dark:border-yellow-800 p-4 text-center">
                    <AlertTriangle className="h-6 w-6 text-yellow-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{warningCount}</p>
                    <p className="text-sm text-slate-500">경고</p>
                </div>
            </div>

            {/* Policy Details */}
            <div className="space-y-4">
                {policyResults.length === 0 && (
                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-green-200 dark:border-green-800 p-6 text-center">
                        <ShieldCheck className="h-10 w-10 text-green-500 mx-auto mb-3" />
                        <h3 className="font-semibold text-slate-900 dark:text-white">정책 위반 없음</h3>
                        <p className="text-sm text-slate-500 mt-1">현재 스캔에 매칭된 차단 또는 경고 정책이 없습니다.</p>
                    </div>
                )}
                {policyResults.map((policy) => (
                    <div
                        key={`${policy.policyId}-${policy.ruleId}-${policy.result}`}
                        className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden"
                    >
                        <div className="p-4 flex items-center gap-4">
                            {getResultIcon(policy.result)}
                            <div className="flex-1">
                                <h3 className="font-semibold text-slate-900 dark:text-white">{policy.policyName}</h3>
                                <p className="text-sm text-slate-500">{policy.message || policy.ruleName}</p>
                            </div>
                            {getResultBadge(policy.result)}
                        </div>
                        {policy.cveIds.length > 0 && (
                            <div className="px-4 pb-4">
                                <div className="bg-slate-50 dark:bg-slate-700/50 rounded-lg p-3">
                                    <p className="text-xs text-slate-500 mb-2">매칭된 취약점 ({policy.count}개):</p>
                                    <div className="flex flex-wrap gap-2">
                                        {policy.cveIds.map((cveId) => (
                                            <Link
                                                key={cveId}
                                                href={`/dashboard/vulnerabilities/${cveId}`}
                                                className="inline-flex items-center gap-1.5 px-2 py-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 rounded text-sm hover:border-blue-400 transition-colors"
                                            >
                                                <span className={`w-2 h-2 rounded-full ${policy.severity === 'CRITICAL' ? 'bg-red-500' :
                                                        policy.severity === 'HIGH' ? 'bg-orange-500' :
                                                            policy.severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-blue-500'
                                                    }`} />
                                                <span className="font-mono text-slate-700 dark:text-slate-300">{cveId}</span>
                                            </Link>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                ))}
            </div>

            {/* Recommendations */}
            {(failedCount > 0 || warningCount > 0) && (
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl p-6">
                    <h3 className="font-semibold text-blue-900 dark:text-blue-400 mb-3 flex items-center gap-2">
                        <Info className="h-5 w-5" />
                        권장 조치
                    </h3>
                    <ul className="space-y-2">
                        <li className="flex items-start gap-2 text-blue-800 dark:text-blue-300">
                            <span className="text-blue-500">•</span>
                            차단 또는 경고된 CVE의 패키지를 수정 버전으로 업데이트하세요.
                        </li>
                        <li className="flex items-start gap-2 text-blue-800 dark:text-blue-300">
                            <span className="text-blue-500">•</span>
                            업무상 즉시 조치가 어렵다면 만료일이 있는 예외 요청을 등록하세요.
                        </li>
                        {results.blockedBy && (
                            <li className="flex items-start gap-2 text-blue-800 dark:text-blue-300">
                                <span className="text-blue-500">•</span>
                                우선 확인할 정책: {results.blockedBy.policyName}
                            </li>
                        )}
                    </ul>
                </div>
            )}
        </div>
    );
}
