'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { AlertCircle, CheckCircle2, Loader2, RefreshCw, Square } from 'lucide-react';
import { AiExportButtons } from '@/components/ai/ai-export-buttons';
import { MarkdownContent } from '@/components/ai/ai-result-panel';
import { cancelAiJob, getAiJob, submitAiJob } from '@/lib/ai-job-client';
import { isAiJobActive, type AiJobResponse } from '@/lib/ai-job-utils';
import { useAiStore } from '@/stores/ai-store';

export default function AiResultPage() {
    const { id } = useParams<{ id: string }>();
    const router = useRouter();
    const [job, setJob] = useState<AiJobResponse | null>(null);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);

    const load = useCallback(async () => {
        try {
            const loaded = await getAiJob(id);
            setJob(loaded);
            if (isAiJobActive(loaded.status) && !useAiStore.getState().pendingJobs[id]) {
                const createdAt = loaded.createdAt || new Date().toISOString();
                useAiStore.getState().addPendingJob({
                    id,
                    action: loaded.action,
                    contextKey: `${loaded.action}:${id}`,
                    status: loaded.status,
                    createdAt,
                    updatedAt: new Date().toISOString(),
                });
            }
            setError('');
        } catch (loadError) {
            setError(loadError instanceof Error ? loadError.message : 'AI 작업을 불러오지 못했습니다.');
        }
    }, [id]);

    useEffect(() => {
        void load();
        const timer = window.setInterval(() => {
            if (!job || isAiJobActive(job.status)) void load();
        }, 2_500);
        return () => window.clearInterval(timer);
    }, [job?.status, load]);

    const cancel = async () => {
        setBusy(true);
        try {
            setJob(await cancelAiJob(id));
        } catch (cancelError) {
            setError(cancelError instanceof Error ? cancelError.message : 'AI 작업을 취소하지 못했습니다.');
        } finally {
            setBusy(false);
        }
    };

    const retry = async () => {
        if (!job?.action || !job.context || typeof job.context !== 'object' || Array.isArray(job.context)) {
            setError('원본 요청 정보가 없어 이 작업을 다시 실행할 수 없습니다.');
            return;
        }
        setBusy(true);
        try {
            const next = await submitAiJob(job.action, job.context as Record<string, unknown>, 0);
            const now = new Date().toISOString();
            useAiStore.getState().addPendingJob({
                id: next.id,
                action: job.action,
                contextKey: `${job.action}:${next.id}`,
                status: next.status,
                createdAt: now,
                updatedAt: now,
            });
            router.replace(`/dashboard/ai-results/${next.id}`);
        } catch (retryError) {
            setError(retryError instanceof Error ? retryError.message : 'AI 작업을 다시 실행하지 못했습니다.');
        } finally {
            setBusy(false);
        }
    };

    const active = job ? isAiJobActive(job.status) : false;

    return (
        <div className="mx-auto max-w-6xl space-y-6 p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">AI 분석 결과</h1>
                    <p className="mt-1 text-sm text-slate-500">작업 ID: {id}</p>
                </div>
                {job?.status === 'SUCCESS' && <AiExportButtons executionId={id} />}
            </div>

            {error && (
                <div role="alert" className="flex items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <span className="flex items-center gap-2"><AlertCircle className="h-4 w-4" />{error}</span>
                    <button type="button" onClick={() => void load()} className="inline-flex items-center gap-1 underline"><RefreshCw className="h-3.5 w-3.5" />다시 불러오기</button>
                </div>
            )}

            {!job && !error && <div className="flex items-center gap-2 rounded-xl border p-6 text-slate-600"><Loader2 className="h-5 w-5 animate-spin" />작업 상태를 확인하고 있습니다.</div>}

            {job && (
                <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900">
                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-6 py-4 dark:border-slate-700">
                        <div className="flex items-center gap-2">
                            {active ? <Loader2 className="h-5 w-5 animate-spin text-blue-600" /> : job.status === 'SUCCESS' ? <CheckCircle2 className="h-5 w-5 text-emerald-600" /> : <AlertCircle className="h-5 w-5 text-red-600" />}
                            <div><p className="font-semibold text-slate-900 dark:text-white">{job.action}</p><p className="text-sm text-slate-500">상태: {job.status}</p></div>
                        </div>
                        {active ? (
                            <button type="button" disabled={busy} onClick={() => void cancel()} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm text-slate-700 disabled:opacity-50"><Square className="h-4 w-4" />작업 취소</button>
                        ) : job.status !== 'SUCCESS' ? (
                            <button type="button" disabled={busy} onClick={() => void retry()} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-sm text-white disabled:opacity-50"><RefreshCw className="h-4 w-4" />다시 실행</button>
                        ) : null}
                    </div>
                    <div className="p-6">
                        {active && <p className="text-slate-600">백그라운드에서 분석 중입니다. 다른 페이지로 이동해도 작업은 계속됩니다.</p>}
                        {job.status === 'SUCCESS' && <MarkdownContent content={job.result || '분석 결과가 비어 있습니다.'} />}
                        {!active && job.status !== 'SUCCESS' && <p className="text-red-600">{job.error || 'AI 분석을 완료하지 못했습니다.'}</p>}
                    </div>
                </section>
            )}
        </div>
    );
}
