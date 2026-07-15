'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { useAiStore, generateAiContextKey } from '@/stores/ai-store';
import { AiActionType } from '@/components/ai/ai-button';
import { AiResult } from '@/components/ai/ai-result-panel';
import { cancelAiJob, submitAiJob } from '@/lib/ai-job-client';

// ============================================
// AI Context Interface
// ============================================
export interface AiContext {
    [key: string]: unknown;
}

// ============================================
// AI Execution Options
// ============================================
export interface AiExecutionOptions {
    /** Custom context key (default: action + entityId) */
    contextKey?: string;
    /** Entity ID for context key generation */
    entityId?: string;
    /** Show result panel on completion */
    showPanel?: boolean;
    /** Callback on success */
    onSuccess?: (result: AiResult) => void;
    /** Callback on error */
    onError?: (error: Error) => void;
}

// ============================================
// AI Execution Hook Return Type
// ============================================
export interface UseAiExecutionReturn {
    /** Execute AI action */
    execute: (context: AiContext) => Promise<AiResult | null>;
    /** Cancel ongoing execution */
    cancel: () => void;
    /** Current loading state */
    isLoading: boolean;
    /** Current progress (0-100) */
    progress: number;
    /** Latest result */
    result: AiResult | null;
    /** Previous results */
    previousResults: AiResult[];
    /** Estimated tokens for context */
    estimateTokens: (context: AiContext) => number;
    /** Open result panel */
    openPanel: () => void;
    /** Close result panel */
    closePanel: () => void;
    /** Is panel open */
    isPanelOpen: boolean;
    /** Error state */
    error: Error | null;
}

// ============================================
// Token Estimation Constants
// ============================================
const TOKENS_PER_CHAR = 0.25; // Rough estimate: 4 chars per token
const BASE_PROMPT_TOKENS: Record<AiActionType, number> = {
    'dashboard.summary': 500,
    'dashboard.riskAnalysis': 800,
    'project.analysis': 600,
    'scan.changeAnalysis': 700,
    'scan.analysis': 1200,
    'vuln.priorityReorder': 400,
    'vuln.actionGuide': 500,
    'vuln.impactAnalysis': 600,
    'policy.interpretation': 400,
    'policy.recommendation': 700,
    'workflow.fixVerification': 500,
    'report.generation': 1000,
    'notification.summary': 300,
    'guide.trivyCommand': 200,
    'admin.permissionRecommendation': 500,
    'admin.complianceMapping': 800,
};

// ============================================
// AI Execution Hook
// ============================================
export function useAiExecution(
    action: AiActionType,
    options: AiExecutionOptions = {}
): UseAiExecutionReturn {
    const {
        contextKey: customContextKey,
        entityId,
        showPanel = true,
        onSuccess,
        onError,
    } = options;

    const contextKey = customContextKey || generateAiContextKey(action, entityId);
    const [submitError, setSubmitError] = useState<Error | null>(null);

    // Store access
    const {
        getLatestResult,
        getPreviousResults,
        setLoading,
        isLoading: checkLoading,
        setProgress,
        getProgress,
        addPendingJob,
        getPendingJob,
        settleJob,
        jobErrors,
        openPanel: storeOpenPanel,
        closePanel: storeClosePanel,
        activePanel,
    } = useAiStore();

    const isLoading = checkLoading(contextKey);
    const progress = getProgress(contextKey);
    const result = getLatestResult(contextKey);
    const previousResults = getPreviousResults(contextKey);
    const isPanelOpen = activePanel?.key === contextKey;
    const storedError = jobErrors[contextKey];
    const error = submitError || (storedError ? new Error(storedError) : null);
    const deliveredResultRef = useRef(result?.id || null);
    const deliveredErrorRef = useRef(storedError || '');

    useEffect(() => {
        if (result && deliveredResultRef.current !== result.id) {
            deliveredResultRef.current = result.id;
            onSuccess?.(result);
        }
    }, [result, onSuccess]);

    useEffect(() => {
        if (storedError && deliveredErrorRef.current !== storedError) {
            deliveredErrorRef.current = storedError;
            onError?.(new Error(storedError));
        }
    }, [storedError, onError]);

    // Estimate tokens for context
    const estimateTokens = useCallback((context: AiContext): number => {
        const contextStr = JSON.stringify(context);
        const contextTokens = Math.ceil(contextStr.length * TOKENS_PER_CHAR);
        const baseTokens = BASE_PROMPT_TOKENS[action] || 500;
        return baseTokens + contextTokens;
    }, [action]);

    // Execute AI action
    const execute = useCallback(async (context: AiContext): Promise<AiResult | null> => {
        setLoading(contextKey, true);
        setProgress(contextKey, 15);
        setSubmitError(null);

        try {
            const submitted = await submitAiJob(action, context, estimateTokens(context));
            const now = new Date().toISOString();
            addPendingJob({
                id: submitted.id,
                action,
                contextKey,
                status: submitted.status,
                createdAt: now,
                updatedAt: now,
            });
            if (showPanel) {
                storeOpenPanel(contextKey, action);
            }
            return null;
        } catch (err) {
            const error = err instanceof Error ? err : new Error('AI 작업을 등록하지 못했습니다.');
            setSubmitError(error);
            setLoading(contextKey, false);
            setProgress(contextKey, 0);
            onError?.(error);
            return null;
        }
    }, [action, contextKey, estimateTokens, addPendingJob, setLoading, setProgress, storeOpenPanel, showPanel, onError]);

    // Cancel execution
    const cancel = useCallback(() => {
        const pending = getPendingJob(contextKey);
        if (!pending) return;
        void cancelAiJob(pending.id)
            .then(settleJob)
            .catch((err: unknown) => {
                const cancelError = err instanceof Error ? err : new Error('AI 작업을 취소하지 못했습니다.');
                setSubmitError(cancelError);
                onError?.(cancelError);
            });
    }, [contextKey, getPendingJob, settleJob, onError]);

    // Panel controls
    const openPanel = useCallback(() => {
        storeOpenPanel(contextKey, action);
    }, [storeOpenPanel, contextKey, action]);

    const closePanel = useCallback(() => {
        storeClosePanel();
    }, [storeClosePanel]);

    return {
        execute,
        cancel,
        isLoading,
        progress,
        result,
        previousResults,
        estimateTokens,
        openPanel,
        closePanel,
        isPanelOpen,
        error,
    };
}

// ============================================
// Context Collectors for Different Screens
// ============================================

/** Collect dashboard context */
export function useDashboardAiContext() {
    return useCallback((overviewData: unknown, projectStats: unknown): AiContext => {
        return {
            screen: 'dashboard',
            overview: overviewData,
            projectStats,
            timestamp: new Date().toISOString(),
        };
    }, []);
}

/** Collect project context */
export function useProjectAiContext() {
    return useCallback((projectData: unknown, scanHistory: unknown): AiContext => {
        return {
            screen: 'project',
            project: projectData,
            scans: scanHistory,
            timestamp: new Date().toISOString(),
        };
    }, []);
}

/** Collect vulnerability context */
export function useVulnerabilityAiContext() {
    return useCallback((vulnerability: unknown, relatedScans?: unknown): AiContext => {
        return {
            screen: 'vulnerability',
            vulnerability,
            relatedScans,
            timestamp: new Date().toISOString(),
        };
    }, []);
}

/** Collect policy context */
export function usePolicyAiContext() {
    return useCallback((policy: unknown, violations?: unknown): AiContext => {
        return {
            screen: 'policy',
            policy,
            violations,
            timestamp: new Date().toISOString(),
        };
    }, []);
}

/** Collect notifications context */
export function useNotificationsAiContext() {
    return useCallback((notifications: unknown[]): AiContext => {
        return {
            screen: 'notifications',
            notifications,
            count: notifications.length,
            timestamp: new Date().toISOString(),
        };
    }, []);
}
