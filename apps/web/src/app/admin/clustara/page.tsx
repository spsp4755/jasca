'use client';

import { useEffect, useState } from 'react';
import { Cable, Loader2, RefreshCw, Save, ShieldCheck } from 'lucide-react';
import {
    ClustaraDelivery,
    ClustaraSettings,
    useClustaraDeliveries,
    useClustaraSettings,
    useRetryClustaraDelivery,
    useTestClustaraConnection,
    useUpdateClustaraSettings,
} from '@/lib/api-hooks';

const defaults: ClustaraSettings = {
    enabled: false,
    autoSend: false,
    baseUrl: '',
    scanPath: '/admin/k8s/security/scans/import',
    sbomPath: '/admin/k8s/security/sboms',
    authType: 'NONE',
    credential: '',
    credentialConfigured: false,
    defaultClusterId: '',
    scanner: 'trivy',
    generator: 'syft',
    timeoutSeconds: 30,
    maxAttempts: 3,
    verifyTls: true,
};

function formatDate(value?: string | null) {
    return value ? new Date(value).toLocaleString('ko-KR') : '-';
}

function statusStyle(status: ClustaraDelivery['status']) {
    if (status === 'SUCCESS') return 'bg-emerald-100 text-emerald-700';
    if (status === 'FAILED') return 'bg-red-100 text-red-700';
    if (status === 'SENDING') return 'bg-blue-100 text-blue-700';
    return 'bg-amber-100 text-amber-700';
}

export default function ClustaraAdminPage() {
    const settingsQuery = useClustaraSettings();
    const deliveriesQuery = useClustaraDeliveries();
    const saveMutation = useUpdateClustaraSettings();
    const testMutation = useTestClustaraConnection();
    const retryMutation = useRetryClustaraDelivery();
    const [form, setForm] = useState(defaults);
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    useEffect(() => {
        if (settingsQuery.data) {
            setForm({ ...defaults, ...settingsQuery.data, credential: '' });
        }
    }, [settingsQuery.data]);

    const update = <K extends keyof ClustaraSettings>(key: K, value: ClustaraSettings[K]) => {
        setForm((current) => ({ ...current, [key]: value }));
    };

    const save = async () => {
        setMessage(null);
        try {
            const saved = await saveMutation.mutateAsync(form);
            setForm({ ...defaults, ...saved, credential: '' });
            setMessage({ type: 'success', text: 'Clustara 연동 설정을 저장했습니다.' });
        } catch (error) {
            setMessage({ type: 'error', text: (error as Error).message });
        }
    };

    const test = async () => {
        setMessage(null);
        try {
            const result = await testMutation.mutateAsync(form);
            setMessage({ type: 'success', text: `${result.message} (${result.durationMs}ms, HTTP ${result.status})` });
        } catch (error) {
            setMessage({ type: 'error', text: (error as Error).message });
        }
    };

    if (settingsQuery.isLoading) {
        return <div className="flex h-64 items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-red-600" /></div>;
    }

    return (
        <div className="space-y-6 p-6">
            <div>
                <h1 className="flex items-center gap-3 text-2xl font-bold text-slate-900 dark:text-white">
                    <Cable className="h-7 w-7 text-red-600" /> Clustara 연동
                </h1>
                <p className="mt-2 text-sm text-slate-500">폐쇄망 Clustara로 Trivy 원본 JSON과 보존된 Syft SBOM을 전송합니다.</p>
            </div>

            {message ? (
                <div className={`rounded-lg border px-4 py-3 text-sm ${message.type === 'success' ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-red-200 bg-red-50 text-red-700'}`}>
                    {message.text}
                </div>
            ) : null}

            <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <div className="grid gap-4 md:grid-cols-2">
                    <Toggle label="연동 활성화" description="수동 전송과 연결 설정을 사용합니다." checked={form.enabled} onChange={(value) => update('enabled', value)} />
                    <Toggle label="스캔 완료 후 자동 전송" description="cluster ID와 image digest가 모두 있을 때만 등록합니다." checked={form.autoSend} onChange={(value) => update('autoSend', value)} />
                    <Field label="Base URL" value={form.baseUrl} placeholder="https://clustara.internal" onChange={(value) => update('baseUrl', value)} />
                    <Field label="기본 cluster_id" value={form.defaultClusterId} placeholder="prod" onChange={(value) => update('defaultClusterId', value)} />
                    <Field label="Trivy Scan API 경로" value={form.scanPath} onChange={(value) => update('scanPath', value)} />
                    <Field label="Syft SBOM API 경로" value={form.sbomPath} onChange={(value) => update('sbomPath', value)} />
                    <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                        인증 방식
                        <select value={form.authType} onChange={(event) => update('authType', event.target.value as ClustaraSettings['authType'])} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 dark:border-slate-600 dark:bg-slate-900">
                            <option value="NONE">인증 없음</option>
                            <option value="X_API_KEY">X-API-Key</option>
                            <option value="BEARER">Authorization: Bearer</option>
                        </select>
                    </label>
                    <Field
                        label={`API Key / Token${form.credentialConfigured ? ' (등록됨)' : ''}`}
                        value={form.credential || ''}
                        type="password"
                        placeholder={form.credentialConfigured ? '변경할 때만 입력' : '인증 비밀값 입력'}
                        disabled={form.authType === 'NONE'}
                        onChange={(value) => update('credential', value)}
                    />
                    <Field label="scanner 쿼리 값" value={form.scanner} onChange={(value) => update('scanner', value)} />
                    <Field label="generator 쿼리 값" value={form.generator} onChange={(value) => update('generator', value)} />
                    <NumberField label="요청 제한시간(초)" value={form.timeoutSeconds} min={5} max={300} onChange={(value) => update('timeoutSeconds', value)} />
                    <NumberField label="최대 전송 시도 횟수" value={form.maxAttempts} min={1} max={10} onChange={(value) => update('maxAttempts', value)} />
                    <div className="md:col-span-2">
                        <Toggle label="TLS 인증서 검증" description="기본 활성화입니다. 사내 CA는 NODE_EXTRA_CA_CERTS로 신뢰시키는 방식을 권장합니다." checked={form.verifyTls} onChange={(value) => update('verifyTls', value)} />
                    </div>
                </div>
                {!form.verifyTls ? <p className="mt-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800">TLS 검증 해제는 임시 진단에만 사용하세요.</p> : null}
                <div className="mt-6 flex flex-wrap gap-3">
                    <button onClick={save} disabled={saveMutation.isPending} className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
                        {saveMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} 저장
                    </button>
                    <button onClick={test} disabled={testMutation.isPending || !form.baseUrl} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200">
                        {testMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} 연결 테스트
                    </button>
                </div>
            </section>

            <section className="rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-700">
                    <div><h2 className="font-semibold text-slate-900 dark:text-white">최근 전송 이력</h2><p className="text-xs text-slate-500">실패 사유와 재시도 횟수를 확인합니다.</p></div>
                    <button onClick={() => deliveriesQuery.refetch()} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"><RefreshCw className={`h-4 w-4 ${deliveriesQuery.isFetching ? 'animate-spin' : ''}`} /></button>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-slate-50 text-xs text-slate-500 dark:bg-slate-900/50"><tr><th className="px-6 py-3">대상</th><th className="px-4 py-3">유형</th><th className="px-4 py-3">상태</th><th className="px-4 py-3">cluster_id</th><th className="px-4 py-3">시도</th><th className="px-4 py-3">결과</th><th className="px-4 py-3">시각</th><th className="px-4 py-3">작업</th></tr></thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                            {(deliveriesQuery.data || []).map((delivery) => (
                                <tr key={delivery.id}>
                                    <td className="max-w-52 truncate px-6 py-4 font-medium">{delivery.scanResult?.artifactName || delivery.scanResult?.imageRef || delivery.scanResultId}</td>
                                    <td className="px-4 py-4">{delivery.type}</td>
                                    <td className="px-4 py-4"><span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusStyle(delivery.status)}`}>{delivery.status}</span></td>
                                    <td className="px-4 py-4">{delivery.clusterId}</td>
                                    <td className="px-4 py-4">{delivery.attempts}/{delivery.maxAttempts}</td>
                                    <td className="max-w-72 px-4 py-4 text-xs text-slate-500"><span title={delivery.lastError || delivery.responseSummary || ''}>{delivery.lastError || delivery.responseSummary || (delivery.httpStatus ? `HTTP ${delivery.httpStatus}` : '-')}</span></td>
                                    <td className="whitespace-nowrap px-4 py-4 text-xs">{formatDate(delivery.succeededAt || delivery.createdAt)}</td>
                                    <td className="px-4 py-4">{delivery.status === 'FAILED' ? <button onClick={() => retryMutation.mutate(delivery.id)} disabled={retryMutation.isPending} className="text-xs font-medium text-red-600">재전송</button> : '-'}</td>
                                </tr>
                            ))}
                            {!deliveriesQuery.data?.length ? <tr><td colSpan={8} className="px-6 py-10 text-center text-slate-500">전송 이력이 없습니다.</td></tr> : null}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
}

function Field({ label, value, onChange, placeholder, type = 'text', disabled = false }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: string; disabled?: boolean }) {
    return <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200">{label}<input type={type} value={value} disabled={disabled} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-normal disabled:bg-slate-100 dark:border-slate-600 dark:bg-slate-900" /></label>;
}

function NumberField({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
    return <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200">{label}<input type="number" value={value} min={min} max={max} onChange={(event) => onChange(Number(event.target.value))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-normal dark:border-slate-600 dark:bg-slate-900" /></label>;
}

function Toggle({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (value: boolean) => void }) {
    return <label className="flex cursor-pointer items-start justify-between gap-4 rounded-lg border border-slate-200 p-4 dark:border-slate-700"><span><span className="block text-sm font-medium text-slate-800 dark:text-slate-100">{label}</span><span className="mt-1 block text-xs text-slate-500">{description}</span></span><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="mt-1 h-4 w-4 rounded border-slate-300 text-red-600" /></label>;
}
