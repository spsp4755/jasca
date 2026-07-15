'use client';

import { useEffect, useState } from 'react';
import { CheckCircle2, Container, Loader2, Save, ShieldCheck } from 'lucide-react';
import {
    HarborSettings,
    useHarborSettings,
    useProjects,
    useTestHarborConnection,
    useUpdateHarborSettings,
} from '@/lib/api-hooks';

const defaults: HarborSettings = {
    enabled: false,
    baseUrl: '',
    username: '',
    password: '',
    passwordConfigured: false,
    allowedProjects: [],
    defaultProjectId: '',
    webhookSecret: '',
    webhookSecretConfigured: false,
    autoScanOnPush: false,
};

export default function HarborAdminPage() {
    const settingsQuery = useHarborSettings();
    const projectsQuery = useProjects();
    const saveMutation = useUpdateHarborSettings();
    const testMutation = useTestHarborConnection();
    const [form, setForm] = useState<HarborSettings>(defaults);
    const [allowedProjectsInput, setAllowedProjectsInput] = useState('');
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    useEffect(() => {
        if (!settingsQuery.data) return;

        setForm({ ...defaults, ...settingsQuery.data, password: '', webhookSecret: '' });
        setAllowedProjectsInput((settingsQuery.data.allowedProjects || []).join(', '));
    }, [settingsQuery.data]);

    const update = <K extends keyof HarborSettings>(key: K, value: HarborSettings[K]) => {
        setForm((current) => ({ ...current, [key]: value }));
    };

    const save = async () => {
        setMessage(null);
        try {
            const saved = await saveMutation.mutateAsync({
                ...form,
                allowedProjects: allowedProjectsInput.split(',').map((project) => project.trim()).filter(Boolean),
            });
            setForm({ ...defaults, ...saved, password: '', webhookSecret: '' });
            setAllowedProjectsInput(saved.allowedProjects.join(', '));
            setMessage({ type: 'success', text: 'Harbor settings saved.' });
        } catch (error) {
            setMessage({ type: 'error', text: (error as Error).message });
        }
    };

    const testConnection = async () => {
        setMessage(null);
        try {
            const result = await testMutation.mutateAsync();
            setMessage({ type: 'success', text: `Connected to Harbor. ${result.projectCount} project(s) available.` });
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
                    <Container className="h-7 w-7 text-red-600" /> Harbor integration
                </h1>
                <p className="mt-2 text-sm text-slate-500">Browse approved Harbor images and scan immutable digests with Trivy.</p>
            </div>

            {message ? (
                <div className={`rounded-lg border px-4 py-3 text-sm ${message.type === 'success' ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-red-200 bg-red-50 text-red-700'}`}>
                    {message.text}
                </div>
            ) : null}

            <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <div className="grid gap-4 md:grid-cols-2">
                    <Toggle label="Enable Harbor integration" description="Allows approved users to browse and scan Harbor images." checked={form.enabled} onChange={(value) => update('enabled', value)} />
                    <Toggle label="Scan pushed artifacts automatically" description="Accepts approved Harbor Push Artifact webhooks for the default JASCA project." checked={form.autoScanOnPush} onChange={(value) => update('autoScanOnPush', value)} />
                    <Field label="Harbor URL" value={form.baseUrl} placeholder="https://harbor.internal" onChange={(value) => update('baseUrl', value)} />
                    <Field label="Robot account" value={form.username} placeholder="robot$jasca" onChange={(value) => update('username', value)} />
                    <Field label={`Robot token${form.passwordConfigured ? ' (configured)' : ''}`} value={form.password || ''} type="password" placeholder={form.passwordConfigured ? 'Leave blank to keep the existing token' : 'Enter the Harbor robot token'} onChange={(value) => update('password', value)} />
                    <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                        Default JASCA project
                        <select value={form.defaultProjectId} onChange={(event) => update('defaultProjectId', event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-normal dark:border-slate-600 dark:bg-slate-900">
                            <option value="">Select a project for webhook scans</option>
                            {(projectsQuery.data?.data || []).map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
                        </select>
                    </label>
                    <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200 md:col-span-2">
                        Allowed Harbor projects
                        <input value={allowedProjectsInput} placeholder="payments, platform" onChange={(event) => setAllowedProjectsInput(event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-normal dark:border-slate-600 dark:bg-slate-900" />
                        <span className="block text-xs font-normal text-slate-500">Comma-separated. Leave empty to permit all Harbor projects.</span>
                    </label>
                    <Field label={`Webhook secret${form.webhookSecretConfigured ? ' (configured)' : ''}`} value={form.webhookSecret || ''} type="password" placeholder={form.webhookSecretConfigured ? 'Leave blank to keep the existing secret' : 'Enter a webhook secret'} onChange={(value) => update('webhookSecret', value)} />
                </div>

                <div className="mt-6 flex flex-wrap gap-3">
                    <button onClick={save} disabled={saveMutation.isPending} className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
                        {saveMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save settings
                    </button>
                    <button onClick={testConnection} disabled={testMutation.isPending || !form.baseUrl} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200">
                        {testMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Test connection
                    </button>
                </div>
            </section>

            <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white"><CheckCircle2 className="h-5 w-5 text-emerald-600" /> Harbor webhook</h2>
                <p className="mt-2 text-sm text-slate-500">Create a Harbor webhook for the Push Artifact event after saving the secret.</p>
                <dl className="mt-4 space-y-3 text-sm">
                    <div><dt className="font-medium text-slate-700 dark:text-slate-200">Webhook URL</dt><dd className="mt-1 rounded bg-slate-100 px-3 py-2 font-mono text-xs text-slate-800 dark:bg-slate-900 dark:text-slate-200">https://&lt;JASCA_HOST&gt;/api/harbor/webhook</dd></div>
                    <div><dt className="font-medium text-slate-700 dark:text-slate-200">Authentication header</dt><dd className="mt-1 rounded bg-slate-100 px-3 py-2 font-mono text-xs text-slate-800 dark:bg-slate-900 dark:text-slate-200">Authorization: Bearer &lt;Webhook Secret&gt;</dd></div>
                </dl>
                <p className="mt-3 text-xs text-slate-500">Do not use a Harbor HMAC signature header. JASCA validates the Authorization Bearer value exactly.</p>
            </section>
        </div>
    );
}

function Field({ label, value, onChange, placeholder, type = 'text' }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: string }) {
    return <label className="space-y-2 text-sm font-medium text-slate-700 dark:text-slate-200">{label}<input type={type} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-normal dark:border-slate-600 dark:bg-slate-900" /></label>;
}

function Toggle({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (value: boolean) => void }) {
    return <label className="flex cursor-pointer items-start justify-between gap-4 rounded-lg border border-slate-200 p-4 dark:border-slate-700"><span><span className="block text-sm font-medium text-slate-800 dark:text-slate-100">{label}</span><span className="mt-1 block text-xs text-slate-500">{description}</span></span><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="mt-1 h-4 w-4 rounded border-slate-300 text-red-600" /></label>;
}
