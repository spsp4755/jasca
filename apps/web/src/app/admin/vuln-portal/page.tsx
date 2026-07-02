'use client';

import { useEffect, useMemo, useState } from 'react';
import {
    AlertTriangle,
    CheckCircle,
    Clock,
    Database,
    Globe2,
    KeyRound,
    Loader2,
    RefreshCw,
    Save,
    Search,
    ShieldAlert,
    XCircle,
} from 'lucide-react';

type IntelType = 'VULNERABILITY' | 'KEV' | 'EOL';
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

interface VulnPortalSettings {
    enabled: boolean;
    baseUrl: string;
    apiKey?: string;
    syncIntervalMinutes: number;
    syncVulnerabilities: boolean;
    syncKev: boolean;
    syncEol: boolean;
    requestTimeoutSeconds: number;
    maxPagesPerSync: number;
    allowInsecureTls: boolean;
    lastSyncAt?: string | null;
    lastSyncResult?: {
        success: boolean;
        message: string;
        vulnerabilities: number;
        kev: number;
        eol: number;
        finishedAt: string;
    } | null;
}

interface IntelItem {
    id: string;
    type: IntelType;
    cveId?: string | null;
    title?: string | null;
    description?: string | null;
    severity: Severity;
    vendor?: string | null;
    product?: string | null;
    cvssScore?: number | null;
    epssScore?: number | null;
    isKev: boolean;
    dueDate?: string | null;
    eolDate?: string | null;
    lastSyncedAt: string;
}

interface StatusResponse {
    settings: VulnPortalSettings;
    syncInProgress: boolean;
    latestLog?: any;
    counts: Record<string, number>;
}

const defaultSettings: VulnPortalSettings = {
    enabled: false,
    baseUrl: 'https://vulnportal.kubagents-int.koreacb.com',
    apiKey: '',
    syncIntervalMinutes: 60,
    syncVulnerabilities: true,
    syncKev: true,
    syncEol: true,
    requestTimeoutSeconds: 30,
    maxPagesPerSync: 100,
    allowInsecureTls: false,
    lastSyncAt: null,
    lastSyncResult: null,
};

function getToken() {
    return localStorage.getItem('accessToken') || '';
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(`/api${path}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${getToken()}`,
            ...(options.headers || {}),
        },
    });
    const text = await response.text();
    const data = text ? JSON.parse(text) : null;
    if (!response.ok) {
        throw new Error(data?.message || data?.error || `요청 실패 (${response.status})`);
    }
    return data as T;
}

function severityClass(severity: string) {
    switch (severity) {
        case 'CRITICAL':
            return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
        case 'HIGH':
            return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300';
        case 'MEDIUM':
            return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300';
        case 'LOW':
            return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300';
        default:
            return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300';
    }
}

function formatDate(value?: string | null) {
    if (!value) return '-';
    return new Date(value).toLocaleString('ko-KR');
}

export default function VulnPortalAdminPage() {
    const [settings, setSettings] = useState<VulnPortalSettings>(defaultSettings);
    const [status, setStatus] = useState<StatusResponse | null>(null);
    const [items, setItems] = useState<IntelItem[]>([]);
    const [total, setTotal] = useState(0);
    const [logs, setLogs] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [testing, setTesting] = useState(false);
    const [syncing, setSyncing] = useState(false);
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const [keyword, setKeyword] = useState('');
    const [typeFilter, setTypeFilter] = useState<'ALL' | IntelType>('ALL');
    const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');

    const query = useMemo(() => {
        const params = new URLSearchParams();
        if (keyword.trim()) params.set('keyword', keyword.trim());
        if (typeFilter !== 'ALL') params.set('type', typeFilter);
        if (severityFilter !== 'ALL') params.set('severity', severityFilter);
        params.set('limit', '30');
        return params.toString();
    }, [keyword, typeFilter, severityFilter]);

    const loadAll = async () => {
        setLoading(true);
        try {
            const [settingsData, statusData, intelData, logData] = await Promise.all([
                api<VulnPortalSettings>('/vuln-portal/settings'),
                api<StatusResponse>('/vuln-portal/status'),
                api<{ items: IntelItem[]; total: number }>(`/vuln-portal/intel?${query}`),
                api<any[]>('/vuln-portal/logs?limit=10'),
            ]);
            setSettings({ ...defaultSettings, ...settingsData });
            setStatus(statusData);
            setItems(intelData.items || []);
            setTotal(intelData.total || 0);
            setLogs(logData || []);
        } catch (error: any) {
            setMessage({ type: 'error', text: error.message || 'vuln-portal 정보를 불러오지 못했습니다.' });
        } finally {
            setLoading(false);
        }
    };

    const loadIntel = async () => {
        try {
            const intelData = await api<{ items: IntelItem[]; total: number }>(`/vuln-portal/intel?${query}`);
            setItems(intelData.items || []);
            setTotal(intelData.total || 0);
        } catch (error: any) {
            setMessage({ type: 'error', text: error.message || '인텔리전스 목록 조회 실패' });
        }
    };

    useEffect(() => {
        loadAll();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        if (!loading) loadIntel();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [query]);

    const updateSetting = <K extends keyof VulnPortalSettings>(key: K, value: VulnPortalSettings[K]) => {
        setSettings((prev) => ({ ...prev, [key]: value }));
    };

    const saveSettings = async () => {
        setSaving(true);
        setMessage(null);
        try {
            const saved = await api<VulnPortalSettings>('/vuln-portal/settings', {
                method: 'PUT',
                body: JSON.stringify(settings),
            });
            setSettings({ ...defaultSettings, ...saved });
            setMessage({ type: 'success', text: 'vuln-portal 연동 설정을 저장했습니다.' });
            await loadAll();
        } catch (error: any) {
            setMessage({ type: 'error', text: error.message || '설정 저장 실패' });
        } finally {
            setSaving(false);
        }
    };

    const testConnection = async () => {
        setTesting(true);
        setMessage(null);
        try {
            const result = await api<any>('/vuln-portal/test', {
                method: 'POST',
                body: JSON.stringify(settings),
            });
            setMessage({ type: 'success', text: `${result.message} 총 ${result.sample?.total ?? 0}건 확인` });
        } catch (error: any) {
            setMessage({ type: 'error', text: error.message || '연결 테스트 실패' });
        } finally {
            setTesting(false);
        }
    };

    const syncNow = async () => {
        setSyncing(true);
        setMessage(null);
        try {
            const result = await api<any>('/vuln-portal/sync', { method: 'POST' });
            setMessage({ type: 'success', text: result.message || '동기화가 완료되었습니다.' });
            await loadAll();
        } catch (error: any) {
            setMessage({ type: 'error', text: error.message || '동기화 실패' });
        } finally {
            setSyncing(false);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            </div>
        );
    }

    const counts = status?.counts || {};

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <Globe2 className="h-7 w-7 text-blue-600" />
                        Vuln Portal 연동
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1">
                        vuln-portal의 CVE, KEV, EOL 정보를 JASCA로 가져와 보강 인텔리전스로 관리합니다.
                    </p>
                </div>
                <div className="flex gap-2">
                    <button onClick={loadAll} className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2">
                        <RefreshCw className="h-4 w-4" />
                        새로고침
                    </button>
                    <button onClick={syncNow} disabled={syncing || status?.syncInProgress} className="px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2">
                        {syncing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
                        즉시 동기화
                    </button>
                </div>
            </div>

            {message && (
                <div className={`rounded-lg p-4 flex items-start gap-3 ${
                    message.type === 'success'
                        ? 'bg-green-50 text-green-800 border border-green-200 dark:bg-green-900/20 dark:text-green-200 dark:border-green-800'
                        : 'bg-red-50 text-red-800 border border-red-200 dark:bg-red-900/20 dark:text-red-200 dark:border-red-800'
                }`}>
                    {message.type === 'success' ? <CheckCircle className="h-5 w-5 mt-0.5" /> : <XCircle className="h-5 w-5 mt-0.5" />}
                    <span>{message.text}</span>
                </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <StatCard label="CVE 인텔리전스" value={counts.VULNERABILITY || 0} icon={<ShieldAlert />} />
                <StatCard label="KEV" value={counts.KEV || 0} icon={<AlertTriangle />} />
                <StatCard label="EOL" value={counts.EOL || 0} icon={<Clock />} />
                <StatCard label="최근 동기화" value={settings.lastSyncAt ? formatDate(settings.lastSyncAt) : '-'} icon={<RefreshCw />} small />
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                <section className="xl:col-span-1 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 space-y-5">
                    <div>
                        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">연동 설정</h2>
                        <p className="text-sm text-slate-500 mt-1">방화벽 개통 후 URL과 API Key를 저장하고 연결 테스트를 실행하세요.</p>
                    </div>

                    <label className="flex items-center justify-between gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-800">
                        <span>
                            <span className="block font-medium text-slate-900 dark:text-white">주기 동기화 활성화</span>
                            <span className="text-xs text-slate-500">켜두면 설정된 주기로 자동 조회합니다.</span>
                        </span>
                        <input type="checkbox" checked={settings.enabled} onChange={(e) => updateSetting('enabled', e.target.checked)} className="h-5 w-5" />
                    </label>

                    <Field label="Base URL">
                        <input value={settings.baseUrl} onChange={(e) => updateSetting('baseUrl', e.target.value)} placeholder="https://vulnportal.kubagents-int.koreacb.com" className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-white" />
                    </Field>

                    <Field label="API Key">
                        <div className="relative">
                            <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                            <input value={settings.apiKey || ''} onChange={(e) => updateSetting('apiKey', e.target.value)} placeholder="vp_xxxxx" className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-white" />
                        </div>
                    </Field>

                    <div className="grid grid-cols-2 gap-3">
                        <Field label="동기화 주기(분)">
                            <input type="number" min={5} max={1440} value={settings.syncIntervalMinutes} onChange={(e) => updateSetting('syncIntervalMinutes', Number(e.target.value))} className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-white" />
                        </Field>
                        <Field label="타임아웃(초)">
                            <input type="number" min={5} max={300} value={settings.requestTimeoutSeconds} onChange={(e) => updateSetting('requestTimeoutSeconds', Number(e.target.value))} className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-white" />
                        </Field>
                    </div>

                    <Field label="동기화 대상">
                        <div className="grid grid-cols-3 gap-2">
                            {[
                                ['syncVulnerabilities', 'CVE'],
                                ['syncKev', 'KEV'],
                                ['syncEol', 'EOL'],
                            ].map(([key, label]) => (
                                <button key={key} type="button" onClick={() => updateSetting(key as keyof VulnPortalSettings, !settings[key as keyof VulnPortalSettings] as any)} className={`px-3 py-2 rounded-lg text-sm border ${
                                    settings[key as keyof VulnPortalSettings]
                                        ? 'bg-blue-50 border-blue-300 text-blue-700 dark:bg-blue-900/30 dark:border-blue-700 dark:text-blue-200'
                                        : 'bg-white border-slate-300 text-slate-500 dark:bg-slate-950 dark:border-slate-700'
                                }`}>
                                    {label}
                                </button>
                            ))}
                        </div>
                    </Field>

                    <label className="flex items-start gap-3 text-sm text-slate-600 dark:text-slate-300">
                        <input type="checkbox" checked={settings.allowInsecureTls} onChange={(e) => updateSetting('allowInsecureTls', e.target.checked)} className="mt-1" />
                        <span>TLS 인증서 검증 비활성화. 사내 자체 인증서 문제로 연결 테스트가 실패할 때만 임시로 사용하세요.</span>
                    </label>

                    <div className="flex gap-2">
                        <button onClick={saveSettings} disabled={saving} className="flex-1 px-4 py-2 rounded-lg bg-slate-900 text-white dark:bg-white dark:text-slate-900 disabled:opacity-50 flex items-center justify-center gap-2">
                            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                            저장
                        </button>
                        <button onClick={testConnection} disabled={testing} className="flex-1 px-4 py-2 rounded-lg bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 flex items-center justify-center gap-2">
                            {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle className="h-4 w-4" />}
                            연결 테스트
                        </button>
                    </div>
                </section>

                <section className="xl:col-span-2 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6">
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between mb-4">
                        <div>
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">동기화된 인텔리전스</h2>
                            <p className="text-sm text-slate-500">총 {total.toLocaleString()}건</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            <div className="relative">
                                <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                                <input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="CVE, 제품, 벤더 검색" className="w-56 pl-9 pr-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm" />
                            </div>
                            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as any)} className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm">
                                <option value="ALL">전체 유형</option>
                                <option value="VULNERABILITY">CVE</option>
                                <option value="KEV">KEV</option>
                                <option value="EOL">EOL</option>
                            </select>
                            <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as any)} className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm">
                                <option value="ALL">전체 심각도</option>
                                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((s) => <option key={s} value={s}>{s}</option>)}
                            </select>
                        </div>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="text-left text-slate-500 border-b border-slate-200 dark:border-slate-800">
                                <tr>
                                    <th className="py-3 pr-3">유형</th>
                                    <th className="py-3 pr-3">식별자</th>
                                    <th className="py-3 pr-3">제목/제품</th>
                                    <th className="py-3 pr-3">심각도</th>
                                    <th className="py-3 pr-3">CVSS/EPSS</th>
                                    <th className="py-3 pr-3">동기화</th>
                                </tr>
                            </thead>
                            <tbody>
                                {items.map((item) => (
                                    <tr key={item.id} className="border-b border-slate-100 dark:border-slate-800 text-slate-700 dark:text-slate-200">
                                        <td className="py-3 pr-3">{item.type}</td>
                                        <td className="py-3 pr-3 font-mono">{item.cveId || item.id.slice(0, 8)}</td>
                                        <td className="py-3 pr-3">
                                            <div className="font-medium text-slate-900 dark:text-white">{item.title || item.product || '-'}</div>
                                            <div className="text-xs text-slate-500">{[item.vendor, item.product].filter(Boolean).join(' / ') || '-'}</div>
                                        </td>
                                        <td className="py-3 pr-3">
                                            <span className={`px-2 py-1 rounded-full text-xs ${severityClass(item.severity)}`}>{item.severity}</span>
                                        </td>
                                        <td className="py-3 pr-3">
                                            <div>CVSS {item.cvssScore ?? '-'}</div>
                                            <div className="text-xs text-slate-500">EPSS {item.epssScore ?? '-'}</div>
                                        </td>
                                        <td className="py-3 pr-3">{formatDate(item.lastSyncedAt)}</td>
                                    </tr>
                                ))}
                                {!items.length && (
                                    <tr>
                                        <td colSpan={6} className="py-10 text-center text-slate-500">동기화된 데이터가 없습니다.</td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>

            <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">최근 동기화 이력</h2>
                <div className="space-y-2">
                    {logs.map((log) => (
                        <div key={log.id} className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 p-3 rounded-lg bg-slate-50 dark:bg-slate-800">
                            <div className="flex items-center gap-3">
                                {log.status === 'SUCCESS' ? <CheckCircle className="h-5 w-5 text-green-600" /> : log.status === 'FAILED' ? <XCircle className="h-5 w-5 text-red-600" /> : <Loader2 className="h-5 w-5 animate-spin text-blue-600" />}
                                <div>
                                    <div className="font-medium text-slate-900 dark:text-white">{log.status}</div>
                                    <div className="text-xs text-slate-500">{log.message || log.error || '-'}</div>
                                </div>
                            </div>
                            <div className="text-sm text-slate-500">
                                CVE {log.vulnerabilities} / KEV {log.kev} / EOL {log.eol} · {formatDate(log.startedAt)}
                            </div>
                        </div>
                    ))}
                    {!logs.length && <div className="text-sm text-slate-500">아직 동기화 이력이 없습니다.</div>}
                </div>
            </section>
        </div>
    );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <label className="block">
            <span className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{label}</span>
            {children}
        </label>
    );
}

function StatCard({ label, value, icon, small = false }: { label: string; value: React.ReactNode; icon: React.ReactElement; small?: boolean }) {
    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 flex items-center gap-4">
            <div className="p-3 rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-300">
                {icon}
            </div>
            <div>
                <div className="text-sm text-slate-500">{label}</div>
                <div className={`${small ? 'text-sm' : 'text-2xl'} font-bold text-slate-900 dark:text-white`}>{value}</div>
            </div>
        </div>
    );
}
