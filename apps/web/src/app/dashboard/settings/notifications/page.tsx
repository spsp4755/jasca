'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
    AlertTriangle,
    ArrowLeft,
    Bell,
    CheckCircle,
    Clock,
    FileWarning,
    Loader2,
    Save,
    ShieldAlert,
    ShieldCheck,
    Siren,
} from 'lucide-react';
import {
    type NotificationSettings,
    useNotificationSettings,
    useUpdateNotificationSettings,
} from '@/lib/api-hooks';

const DEFAULT_SETTINGS: NotificationSettings = {
    emailAlerts: true,
    criticalOnly: false,
    weeklyDigest: true,
    scanComplete: true,
    criticalVulns: true,
    highVulns: true,
    policyViolations: true,
    exceptionAlerts: true,
};

const EVENT_SETTINGS: Array<{
    key: keyof NotificationSettings;
    title: string;
    description: string;
    icon: typeof Bell;
    tone: string;
}> = [
    {
        key: 'scanComplete',
        title: '스캔 완료',
        description: 'Trivy 직접 검사 또는 결과 업로드가 완료될 때마다 알림을 받습니다. 같은 파일을 반복 스캔해도 매번 생성됩니다.',
        icon: CheckCircle,
        tone: 'text-green-600 bg-green-50 dark:bg-green-950/30',
    },
    {
        key: 'criticalVulns',
        title: 'Critical 취약점',
        description: 'Critical 취약점이 발견되면 즉시 알림을 받습니다.',
        icon: Siren,
        tone: 'text-red-600 bg-red-50 dark:bg-red-950/30',
    },
    {
        key: 'highVulns',
        title: 'High 취약점',
        description: 'High 취약점이 발견되면 알림을 받습니다. Critical 전용을 켜면 High 알림은 제외됩니다.',
        icon: AlertTriangle,
        tone: 'text-orange-600 bg-orange-50 dark:bg-orange-950/30',
    },
    {
        key: 'policyViolations',
        title: '정책 위반',
        description: '관리자가 설정한 정책 또는 임계값에 위반되는 결과가 생기면 알림을 받습니다.',
        icon: FileWarning,
        tone: 'text-amber-600 bg-amber-50 dark:bg-amber-950/30',
    },
    {
        key: 'exceptionAlerts',
        title: '예외 처리',
        description: '취약점 예외 생성, 만료, 상태 변경과 관련된 알림을 받습니다.',
        icon: ShieldCheck,
        tone: 'text-blue-600 bg-blue-50 dark:bg-blue-950/30',
    },
    {
        key: 'weeklyDigest',
        title: '주간 요약',
        description: '주요 스캔/취약점 현황을 주간 요약 형태로 받습니다.',
        icon: Clock,
        tone: 'text-slate-600 bg-slate-50 dark:bg-slate-900',
    },
];

function mergeSettings(settings?: Partial<NotificationSettings>): NotificationSettings {
    return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

function Toggle({
    checked,
    disabled,
    onClick,
    label,
}: {
    checked: boolean;
    disabled?: boolean;
    onClick: () => void;
    label: string;
}) {
    return (
        <button
            type="button"
            role="switch"
            aria-checked={checked}
            aria-label={`${label} ${checked ? '활성' : '비활성'}`}
            disabled={disabled}
            onClick={onClick}
            className={`inline-flex min-w-[112px] items-center justify-between gap-2 rounded-full border px-2 py-1 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                checked
                    ? 'border-blue-200 bg-blue-600 text-white shadow-sm shadow-blue-600/20'
                    : 'border-slate-300 bg-white text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300'
            }`}
        >
            <span
                className={`h-5 w-5 rounded-full bg-white shadow transition-transform ${
                    checked ? 'order-2' : 'order-1 bg-slate-300 dark:bg-slate-500'
                }`}
            />
            <span className={checked ? 'order-1 pl-2' : 'order-2 pr-2'}>
                {checked ? '활성' : '비활성'}
            </span>
        </button>
    );
}

export default function NotificationSettingsPage() {
    const { data, isLoading, error, refetch } = useNotificationSettings();
    const updateMutation = useUpdateNotificationSettings();
    const [settings, setSettings] = useState<NotificationSettings>(DEFAULT_SETTINGS);
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        if (data) {
            setSettings(mergeSettings(data));
        }
    }, [data]);

    const updateLocal = (key: keyof NotificationSettings, value: boolean) => {
        setSettings((prev) => ({ ...prev, [key]: value }));
    };

    const save = async () => {
        await updateMutation.mutateAsync(settings);
        await refetch();
        setSaved(true);
        window.setTimeout(() => setSaved(false), 2500);
    };

    const eventDisabled = isLoading || updateMutation.isPending || !settings.emailAlerts;

    return (
        <div className="min-h-screen bg-slate-50 p-6 dark:bg-slate-950">
            <div className="mx-auto max-w-5xl space-y-6">
                <div className="flex items-center justify-between gap-4">
                    <div>
                        <Link
                            href="/dashboard/settings"
                            className="mb-4 inline-flex items-center gap-2 text-sm text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
                        >
                            <ArrowLeft className="h-4 w-4" />
                            설정으로 돌아가기
                        </Link>
                        <div className="flex items-center gap-4">
                            <div className="rounded-2xl bg-blue-600 p-3 text-white shadow-lg shadow-blue-600/20">
                                <Bell className="h-7 w-7" />
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold text-slate-950 dark:text-white">알림 설정</h1>
                                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                                    JASCA 내부 알림을 이벤트별로 세밀하게 조절합니다.
                                </p>
                            </div>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={save}
                        disabled={isLoading || updateMutation.isPending}
                        className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        {updateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                        저장
                    </button>
                </div>

                {error && (
                    <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300">
                        알림 설정을 불러오지 못했습니다. 새로고침 후 다시 시도해 주세요.
                    </div>
                )}

                {saved && (
                    <div className="rounded-xl border border-green-200 bg-green-50 p-4 text-sm font-medium text-green-700 dark:border-green-900 dark:bg-green-950/30 dark:text-green-300">
                        알림 설정이 저장되어 즉시 적용됩니다.
                    </div>
                )}

                <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
                    <div className="flex items-start justify-between gap-6">
                        <div className="flex gap-4">
                            <div className="rounded-xl bg-slate-100 p-3 text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                                <ShieldAlert className="h-6 w-6" />
                            </div>
                            <div>
                                <h2 className="text-lg font-semibold text-slate-950 dark:text-white">전체 알림</h2>
                                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                                    끄면 스캔 완료, 취약점, 정책 위반 등 모든 개인 알림 생성이 중지됩니다.
                                </p>
                            </div>
                        </div>
                        <Toggle
                            checked={settings.emailAlerts}
                            disabled={isLoading || updateMutation.isPending}
                            label="전체 알림"
                            onClick={() => updateLocal('emailAlerts', !settings.emailAlerts)}
                        />
                    </div>
                </section>

                <section className="grid gap-4 md:grid-cols-2">
                    {EVENT_SETTINGS.map((item) => {
                        const Icon = item.icon;
                        const checked = Boolean(settings[item.key]);
                        return (
                            <div
                                key={item.key}
                                className={`rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition dark:border-slate-800 dark:bg-slate-900 ${
                                    eventDisabled ? 'opacity-60' : ''
                                }`}
                            >
                                <div className="flex items-start justify-between gap-4">
                                    <div className="flex gap-3">
                                        <div className={`rounded-xl p-2.5 ${item.tone}`}>
                                            <Icon className="h-5 w-5" />
                                        </div>
                                        <div>
                                            <h3 className="font-semibold text-slate-950 dark:text-white">{item.title}</h3>
                                            <p className="mt-1 text-sm leading-6 text-slate-500 dark:text-slate-400">{item.description}</p>
                                        </div>
                                    </div>
                                    <Toggle
                                        checked={checked}
                                        disabled={eventDisabled}
                                        label={item.title}
                                        onClick={() => updateLocal(item.key, !checked)}
                                    />
                                </div>
                            </div>
                        );
                    })}
                </section>

                <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
                    <div className="flex items-start justify-between gap-6">
                        <div>
                            <h2 className="text-lg font-semibold text-slate-950 dark:text-white">Critical 전용 모드</h2>
                            <p className="mt-1 text-sm leading-6 text-slate-500 dark:text-slate-400">
                                켜면 취약점/정책 알림은 Critical 등급만 받습니다. 스캔 완료 알림은 위의 스캔 완료 설정을 따릅니다.
                            </p>
                        </div>
                        <Toggle
                            checked={settings.criticalOnly}
                            disabled={eventDisabled}
                            label="Critical 전용 모드"
                            onClick={() => updateLocal('criticalOnly', !settings.criticalOnly)}
                        />
                    </div>
                </section>
            </div>
        </div>
    );
}
