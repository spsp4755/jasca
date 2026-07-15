import type { AiActionType } from '@/components/ai/ai-button';
import type { AiContext } from '@/hooks/use-ai-execution';
import { useAiStore } from '@/stores/ai-store';
import { fetchWithAuth } from '@/lib/api/fetch-utils';
import { isAiJobActive, type AiJobResponse } from '@/lib/ai-job-utils';

const inFlight = new Set<string>();

async function readJson<T>(response: Response): Promise<T> {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = body as { message?: string };
        throw new Error(error.message || `요청에 실패했습니다. (HTTP ${response.status})`);
    }
    return body as T;
}

export async function submitAiJob(
    action: AiActionType,
    context: AiContext,
    estimatedTokens: number,
): Promise<{ id: string; status: 'QUEUED' | 'RUNNING' }> {
    const response = await fetchWithAuth('/api/ai/jobs', {
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({ action, context, estimatedTokens }),
    });
    return readJson(response);
}

export async function getAiJob(id: string): Promise<AiJobResponse> {
    return readJson(await fetchWithAuth(`/api/ai/jobs/${encodeURIComponent(id)}`, {
        credentials: 'include',
    }));
}

export async function cancelAiJob(id: string): Promise<AiJobResponse> {
    return readJson(await fetchWithAuth(`/api/ai/jobs/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'include',
    }));
}

export async function refreshAiJob(id: string): Promise<void> {
    if (inFlight.has(id)) return;
    inFlight.add(id);
    try {
        const job = await getAiJob(id);
        const store = useAiStore.getState();
        if (isAiJobActive(job.status)) {
            const pending = store.pendingJobs[id];
            if (pending && pending.status !== job.status) store.updatePendingJob(id, job.status);
        } else {
            store.settleJob(job);
        }
    } catch (error) {
        // Keep the persisted job so a temporary network outage can recover on the next poll.
        console.warn('AI 작업 상태를 확인하지 못했습니다.', error);
    } finally {
        inFlight.delete(id);
    }
}
