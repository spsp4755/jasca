'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, ShieldCheck, Loader2 } from 'lucide-react';
import { useProjects, useOwaspComplianceReport } from '@/lib/api-hooks';

function SeverityCell({ value, className }: { value: number; className: string }) {
    if (!value) return <td className="px-4 py-3 text-center text-slate-400">-</td>;
    return <td className={`px-4 py-3 text-center font-medium ${className}`}>{value}</td>;
}

export default function CompliancePage() {
    const [projectId, setProjectId] = useState('');
    const { data: projectsData } = useProjects();
    const { data: report, isLoading } = useOwaspComplianceReport(projectId || undefined);

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-4">
                <Link
                    href="/dashboard/reports"
                    className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                >
                    <ArrowLeft className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                </Link>
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <ShieldCheck className="h-6 w-6 text-violet-600" />
                        컴플라이언스 리포트
                    </h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                        미해결 취약점을 OWASP Top 10 (2021) / CWE Top 25 (2024) 기준으로 분류합니다.
                    </p>
                </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">프로젝트</label>
                <select
                    value={projectId}
                    onChange={(e) => setProjectId(e.target.value)}
                    className="w-full max-w-md px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white text-sm"
                >
                    <option value="">프로젝트를 선택하세요</option>
                    {(projectsData?.data || []).map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                </select>
            </div>

            {isLoading && (
                <div className="flex items-center justify-center py-12 text-slate-500">
                    <Loader2 className="h-6 w-6 animate-spin mr-2" /> 분석 중...
                </div>
            )}

            {report && !isLoading && (
                <>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                            <p className="text-sm text-slate-500 dark:text-slate-400">미해결 취약점</p>
                            <p className="text-3xl font-bold text-slate-900 dark:text-white mt-1">{report.totalOpenVulnerabilities}</p>
                        </div>
                        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                            <p className="text-sm text-slate-500 dark:text-slate-400">OWASP Top 10 해당 카테고리</p>
                            <p className="text-3xl font-bold text-violet-600 mt-1">{report.owaspTop10.length}<span className="text-base font-normal text-slate-400"> / 10</span></p>
                        </div>
                        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                            <p className="text-sm text-slate-500 dark:text-slate-400">CWE 미매핑</p>
                            <p className="text-3xl font-bold text-slate-900 dark:text-white mt-1">{report.unmappedCount}</p>
                        </div>
                    </div>

                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">OWASP Top 10 (2021)</h3>
                        </div>
                        {report.owaspTop10.length === 0 ? (
                            <p className="px-6 py-8 text-sm text-slate-500 text-center">OWASP Top 10에 해당하는 미해결 취약점이 없습니다.</p>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="text-left text-xs text-slate-500 uppercase border-b border-slate-200 dark:border-slate-700">
                                            <th className="px-6 py-3">카테고리</th>
                                            <th className="px-4 py-3 text-center">건수</th>
                                            <th className="px-4 py-3 text-center">Critical</th>
                                            <th className="px-4 py-3 text-center">High</th>
                                            <th className="px-4 py-3 text-center">Medium</th>
                                            <th className="px-4 py-3 text-center">Low</th>
                                            <th className="px-6 py-3">관련 CWE</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {report.owaspTop10.map((cat) => (
                                            <tr key={cat.id} className="border-b border-slate-100 dark:border-slate-700/50 last:border-0">
                                                <td className="px-6 py-3">
                                                    <span className="font-semibold text-slate-900 dark:text-white">{cat.id}</span>
                                                    <span className="text-slate-600 dark:text-slate-400 ml-2">{cat.name}</span>
                                                </td>
                                                <td className="px-4 py-3 text-center font-bold text-slate-900 dark:text-white">{cat.count}</td>
                                                <SeverityCell value={cat.critical} className="text-red-600" />
                                                <SeverityCell value={cat.high} className="text-orange-600" />
                                                <SeverityCell value={cat.medium} className="text-yellow-600" />
                                                <SeverityCell value={cat.low} className="text-blue-600" />
                                                <td className="px-6 py-3 text-xs text-slate-500">{cat.cweIds.join(', ')}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">CWE Top 25 (2024)</h3>
                        </div>
                        {report.cweTop25.length === 0 ? (
                            <p className="px-6 py-8 text-sm text-slate-500 text-center">CWE Top 25에 해당하는 미해결 취약점이 없습니다.</p>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="text-left text-xs text-slate-500 uppercase border-b border-slate-200 dark:border-slate-700">
                                            <th className="px-6 py-3">순위</th>
                                            <th className="px-6 py-3">CWE</th>
                                            <th className="px-6 py-3">이름</th>
                                            <th className="px-4 py-3 text-center">건수</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {report.cweTop25.map((cwe) => (
                                            <tr key={cwe.cweId} className="border-b border-slate-100 dark:border-slate-700/50 last:border-0">
                                                <td className="px-6 py-3 font-semibold text-slate-900 dark:text-white">#{cwe.rank}</td>
                                                <td className="px-6 py-3 text-violet-600 font-medium">{cwe.cweId}</td>
                                                <td className="px-6 py-3 text-slate-600 dark:text-slate-400">{cwe.name}</td>
                                                <td className="px-4 py-3 text-center font-bold text-slate-900 dark:text-white">{cwe.count}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </>
            )}
        </div>
    );
}
