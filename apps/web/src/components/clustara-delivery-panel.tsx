'use client';

import { useEffect, useState } from 'react';
import { Cable, Loader2, RefreshCw, RotateCcw, Send } from 'lucide-react';
import { Scan, useClustaraOptions, useQueueClustaraDelivery, useRetryClustaraDelivery, useScanClustaraDeliveries } from '@/lib/api-hooks';
import { useAuthStore } from '@/stores/auth-store';

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;

export function ClustaraDeliveryPanel({ scan }: { scan: Scan }) {
    const optionsQuery = useClustaraOptions();
    const deliveriesQuery = useScanClustaraDeliveries(scan.id);
    const queueMutation = useQueueClustaraDelivery(scan.id);
    const retryMutation = useRetryClustaraDelivery(scan.id);
    const user = useAuthStore((state) => state.user);
    const [clusterId, setClusterId] = useState('');
    const [identifier, setIdentifier] = useState(scan.imageDigest || scan.imageRef || scan.artifactName || `jasca-scan:${scan.id}`);
    const [scanner, setScanner] = useState((scan as any).scanEvidence?.scanner || 'trivy');
    const [generator, setGenerator] = useState('syft');
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    useEffect(() => {
        if (!optionsQuery.data) return;
        setClusterId((value) => value || optionsQuery.data.defaultClusterId);
        setScanner((value: string) => value || optionsQuery.data.scanner);
        setGenerator(optionsQuery.data.generator);
    }, [optionsQuery.data]);

    const canSend = Boolean(user?.roles?.some((role) => ['PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'SYSTEM_ADMIN'].includes(role)));
    const hasSbom = Boolean(scan.artifacts?.some((artifact) => artifact.type === 'CYCLONEDX_JSON'));
    const validDigest = DIGEST_PATTERN.test(identifier.trim());
    const canSubmit = Boolean(optionsQuery.data?.enabled && canSend && clusterId.trim() && identifier.trim());

    const queue = async (type: 'TRIVY' | 'SBOM') => {
        setMessage(null);
        try {
            await queueMutation.mutateAsync({
                type,
                clusterId: clusterId.trim(),
                imageDigest: validDigest ? identifier.trim() : undefined,
                imageRef: validDigest ? undefined : identifier.trim(),
                scanner: scanner.trim(),
                generator: generator.trim(),
            });
            setMessage({ type: 'success', text: `${type} 전송을 대기열에 등록했습니다.` });
        } catch (error) {
            setMessage({ type: 'error', text: (error as Error).message });
        }
    };

    return (
        <section className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-800">
            <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                    <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white"><Cable className="h-5 w-5 text-red-600" /> Clustara 전송</h2>
                    <p className="mt-1 text-sm text-slate-500">Trivy, Checkov, ZAP, Semgrep 결과와 보존된 SBOM을 사내 Clustara에 등록합니다.</p>
                </div>
                <button onClick={() => deliveriesQuery.refetch()} className="rounded-lg border border-slate-200 p-2 text-slate-500 hover:bg-slate-50 dark:border-slate-700"><RefreshCw className={`h-4 w-4 ${deliveriesQuery.isFetching ? 'animate-spin' : ''}`} /></button>
            </div>

            {!optionsQuery.data?.enabled ? <p className="mt-4 rounded-lg bg-slate-50 px-4 py-3 text-sm text-slate-600 dark:bg-slate-900 dark:text-slate-300">관리자에서 Clustara 연동을 활성화해야 전송할 수 있습니다.</p> : null}
            {!canSend ? <p className="mt-4 rounded-lg bg-blue-50 px-4 py-3 text-sm text-blue-700">상태 조회는 가능하지만 수동 전송은 프로젝트 관리자 이상 권한이 필요합니다.</p> : null}
            {message ? <p className={`mt-4 rounded-lg px-4 py-3 text-sm ${message.type === 'success' ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'}`}>{message.text}</p> : null}

            <div className="mt-5 grid gap-4 md:grid-cols-2">
                <Field label="cluster_id" value={clusterId} onChange={setClusterId} placeholder="prod" />
                <Field label="전송 식별자" value={identifier} onChange={setIdentifier} placeholder={`sha256:${'0'.repeat(64)} 또는 registry.internal/team/app:1.0`} />
                <Field label="scanner" value={scanner} onChange={setScanner} />
                <Field label="generator" value={generator} onChange={setGenerator} />
            </div>

            <div className="mt-5 flex flex-wrap gap-3">
                <button onClick={() => queue('TRIVY')} disabled={!canSubmit || queueMutation.isPending} className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
                    {queueMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />} 스캔 결과 전송
                </button>
                <button onClick={() => queue('SBOM')} disabled={!canSubmit || !hasSbom || queueMutation.isPending} title={hasSbom ? undefined : '이 스캔에는 보존된 Syft SBOM이 없습니다.'} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 disabled:opacity-40 dark:border-slate-600 dark:text-slate-200">
                    <Send className="h-4 w-4" /> Syft SBOM 전송
                </button>
                <span className="self-center text-xs text-slate-500">SBOM: {hasSbom ? '보존됨' : '생성되지 않음'}</span>
            </div>
            {!validDigest ? <p className="mt-3 text-xs text-amber-700 dark:text-amber-300">digest 없이 전송합니다. Clustara에서는 전송 식별자를 기준으로 Import하며 SBOM, Admission, 런타임 상관분석 정확도가 제한될 수 있습니다.</p> : null}

            <div className="mt-6 overflow-x-auto border-t border-slate-200 pt-5 dark:border-slate-700">
                <table className="w-full text-left text-sm">
                    <thead className="text-xs text-slate-500"><tr><th className="pb-3">유형</th><th className="pb-3">상태</th><th className="pb-3">시도</th><th className="pb-3">HTTP/결과</th><th className="pb-3">작업</th></tr></thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                        {(deliveriesQuery.data || []).map((delivery) => (
                            <tr key={delivery.id}>
                                <td className="py-3 font-medium">{delivery.type === 'TRIVY' ? `SCAN (${delivery.scanner || 'trivy'})` : `SBOM (${delivery.generator || 'syft'})`}</td>
                                <td className="py-3"><span className={`rounded-full px-2 py-1 text-xs ${delivery.status === 'SUCCESS' ? 'bg-emerald-100 text-emerald-700' : delivery.status === 'FAILED' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}`}>{delivery.status}</span></td>
                                <td className="py-3">{delivery.attempts}/{delivery.maxAttempts}</td>
                                <td className="max-w-96 py-3 text-xs text-slate-500">{delivery.lastError || delivery.responseSummary || (delivery.httpStatus ? `HTTP ${delivery.httpStatus}` : '-')}</td>
                                <td className="py-3">{delivery.status === 'FAILED' && canSend ? <button onClick={() => retryMutation.mutate(delivery.id)} disabled={retryMutation.isPending} className="inline-flex items-center gap-1 text-xs font-medium text-red-600"><RotateCcw className="h-3 w-3" /> 재전송</button> : '-'}</td>
                            </tr>
                        ))}
                        {!deliveriesQuery.data?.length ? <tr><td colSpan={5} className="py-6 text-center text-sm text-slate-500">아직 전송 이력이 없습니다.</td></tr> : null}
                    </tbody>
                </table>
            </div>
        </section>
    );
}

function Field({ label, value, onChange, placeholder, error }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; error?: string }) {
    return <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200">{label}<input value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} className={`w-full rounded-lg border bg-white px-3 py-2 font-mono text-xs font-normal dark:bg-slate-900 ${error ? 'border-red-400' : 'border-slate-300 dark:border-slate-600'}`} />{error ? <span className="block text-xs font-normal text-red-600">{error}</span> : null}</label>;
}
