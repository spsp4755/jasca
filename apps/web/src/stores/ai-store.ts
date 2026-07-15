'use client';

import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { AiResult } from '@/components/ai/ai-result-panel';
import type { AiActionType } from '@/components/ai/ai-button';
import {
    buildAiResult,
    partializeAiState,
    type AiJobResponse,
    type PendingAiJob,
} from '@/lib/ai-job-utils';

interface AiState {
    results: Record<string, AiResult[]>;
    activePanel: { key: string; action: AiActionType } | null;
    loadingStates: Record<string, boolean>;
    progressStates: Record<string, number>;
    pendingJobs: Record<string, PendingAiJob>;
    jobErrors: Record<string, string>;
}

interface AiActions {
    addResult: (key: string, result: AiResult) => void;
    getHistory: (key: string) => AiResult[];
    clearHistory: (key: string) => void;
    openPanel: (key: string, action: AiActionType) => void;
    closePanel: () => void;
    setLoading: (key: string, loading: boolean) => void;
    isLoading: (key: string) => boolean;
    setProgress: (key: string, progress: number) => void;
    getProgress: (key: string) => number;
    getLatestResult: (key: string) => AiResult | null;
    getPreviousResults: (key: string) => AiResult[];
    addPendingJob: (job: PendingAiJob) => void;
    updatePendingJob: (id: string, status: PendingAiJob['status']) => void;
    settleJob: (job: AiJobResponse) => void;
    removePendingJob: (id: string) => void;
    setJobError: (contextKey: string, message: string | null) => void;
    getPendingJob: (contextKey: string) => PendingAiJob | null;
}

const MAX_RESULTS_PER_CONTEXT = 10;

export const useAiStore = create<AiState & AiActions>()(
    persist(
        (set, get) => ({
            results: {},
            activePanel: null,
            loadingStates: {},
            progressStates: {},
            pendingJobs: {},
            jobErrors: {},

            addResult: (key, result) => set((state) => ({
                results: {
                    ...state.results,
                    [key]: [
                        result,
                        ...(state.results[key] || []).filter(existing => existing.id !== result.id),
                    ].slice(0, MAX_RESULTS_PER_CONTEXT),
                },
            })),
            getHistory: key => get().results[key] || [],
            clearHistory: key => set((state) => {
                const { [key]: _removed, ...results } = state.results;
                return { results };
            }),
            openPanel: (key, action) => set({ activePanel: { key, action } }),
            closePanel: () => set({ activePanel: null }),
            setLoading: (key, loading) => set((state) => ({
                loadingStates: { ...state.loadingStates, [key]: loading },
            })),
            isLoading: key => get().loadingStates[key]
                || Object.values(get().pendingJobs).some(job => job.contextKey === key),
            setProgress: (key, progress) => set((state) => ({
                progressStates: { ...state.progressStates, [key]: progress },
            })),
            getProgress: key => {
                const pending = Object.values(get().pendingJobs).find(job => job.contextKey === key);
                if (pending) return pending.status === 'RUNNING' ? 65 : 15;
                return get().progressStates[key] || 0;
            },
            getLatestResult: key => get().results[key]?.[0] || null,
            getPreviousResults: key => (get().results[key] || []).slice(1),

            addPendingJob: job => set((state) => ({
                pendingJobs: { ...state.pendingJobs, [job.id]: job },
                loadingStates: { ...state.loadingStates, [job.contextKey]: true },
                progressStates: { ...state.progressStates, [job.contextKey]: 15 },
                jobErrors: { ...state.jobErrors, [job.contextKey]: '' },
            })),
            updatePendingJob: (id, status) => set((state) => {
                const job = state.pendingJobs[id];
                if (!job) return state;
                return {
                    pendingJobs: {
                        ...state.pendingJobs,
                        [id]: { ...job, status, updatedAt: new Date().toISOString() },
                    },
                    progressStates: {
                        ...state.progressStates,
                        [job.contextKey]: status === 'RUNNING' ? 65 : 15,
                    },
                };
            }),
            settleJob: job => set((state) => {
                const pending = state.pendingJobs[job.id];
                if (!pending) return state;
                const { [job.id]: _removed, ...pendingJobs } = state.pendingJobs;
                const result = buildAiResult(job);
                const message = job.status === 'SUCCESS'
                    ? ''
                    : job.error || (job.status === 'CANCELLED' ? 'AI 분석이 취소되었습니다.' : 'AI 분석에 실패했습니다.');
                return {
                    pendingJobs,
                    results: result ? {
                        ...state.results,
                        [pending.contextKey]: [
                            result,
                            ...(state.results[pending.contextKey] || []).filter(existing => existing.id !== result.id),
                        ].slice(0, MAX_RESULTS_PER_CONTEXT),
                    } : state.results,
                    loadingStates: { ...state.loadingStates, [pending.contextKey]: false },
                    progressStates: { ...state.progressStates, [pending.contextKey]: result ? 100 : 0 },
                    jobErrors: { ...state.jobErrors, [pending.contextKey]: message },
                };
            }),
            removePendingJob: id => set((state) => {
                const job = state.pendingJobs[id];
                if (!job) return state;
                const { [id]: _removed, ...pendingJobs } = state.pendingJobs;
                return {
                    pendingJobs,
                    loadingStates: { ...state.loadingStates, [job.contextKey]: false },
                };
            }),
            setJobError: (contextKey, message) => set((state) => ({
                jobErrors: { ...state.jobErrors, [contextKey]: message || '' },
            })),
            getPendingJob: contextKey => Object.values(get().pendingJobs)
                .find(job => job.contextKey === contextKey) || null,
        }),
        {
            name: 'ai-store',
            storage: createJSONStorage(() => localStorage),
            partialize: partializeAiState,
        },
    ),
);

export function generateAiContextKey(action: AiActionType, entityId?: string): string {
    return entityId ? `${action}:${entityId}` : action;
}
