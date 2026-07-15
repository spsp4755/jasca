import type { AiActionType } from '../components/ai/ai-button';
import type { AiResult } from '../components/ai/ai-result-panel';

export type AiJobStatus = 'QUEUED' | 'RUNNING' | 'SUCCESS' | 'ERROR' | 'TIMEOUT' | 'CANCELLED';

export interface AiJobResponse {
    id: string;
    action: AiActionType;
    status: AiJobStatus;
    result?: string | null;
    context?: Record<string, unknown> | null;
    error?: string | null;
    model?: string | null;
    inputTokens?: number;
    outputTokens?: number;
    durationMs?: number;
    createdAt?: string;
}

export interface PendingAiJob {
    id: string;
    contextKey: string;
    action: AiActionType;
    status: Extract<AiJobStatus, 'QUEUED' | 'RUNNING'>;
    createdAt: string;
    updatedAt: string;
}

export function partializeAiState<T extends { results: unknown; pendingJobs: unknown }>(state: T) {
    return { results: state.results, pendingJobs: state.pendingJobs };
}

export function isAiJobActive(status: AiJobStatus): status is Extract<AiJobStatus, 'QUEUED' | 'RUNNING'> {
    return status === 'QUEUED' || status === 'RUNNING';
}

export function buildAiResult(job: AiJobResponse): AiResult | null {
    if (job.status !== 'SUCCESS') return null;

    return {
        id: job.id,
        action: job.action,
        content: job.result || '',
        metadata: {
            model: job.model || undefined,
            inputTokens: job.inputTokens,
            outputTokens: job.outputTokens,
            durationMs: job.durationMs,
        },
        createdAt: job.createdAt ? new Date(job.createdAt) : new Date(),
        isSaved: true,
    };
}

export async function validateDownloadPayload(blob: Blob, contentType: string): Promise<Blob> {
    if (blob.size === 0) throw new Error('다운로드한 보고서가 비어 있습니다.');

    const prefix = (await blob.slice(0, 512).text()).trim();
    if (contentType.toLowerCase().includes('json') || prefix.startsWith('{') || prefix.startsWith('[')) {
        try {
            const body = JSON.parse(await blob.text()) as { message?: string; error?: string };
            throw new Error(body.message || body.error || '보고서 대신 오류 응답을 받았습니다.');
        } catch (error) {
            if (error instanceof SyntaxError) {
                throw new Error('보고서 대신 잘못된 JSON 응답을 받았습니다.');
            }
            throw error;
        }
    }

    return blob;
}

export function getDownloadFileName(disposition: string | null, fallbackName: string): string {
    if (!disposition) return fallbackName;

    const encoded = /filename\*=UTF-8''([^;]+)/i.exec(disposition)?.[1];
    if (encoded) {
        try {
            return decodeURIComponent(encoded);
        } catch {
            return encoded;
        }
    }

    return /filename="?([^";]+)"?/i.exec(disposition)?.[1] || fallbackName;
}

export function buildAiExportUrl(
    executionId: string,
    format: 'pdf' | 'docx',
    scope: 'summary' | 'full',
): string {
    return `/api/ai/history/${encodeURIComponent(executionId)}/export?format=${format}&scope=${scope}`;
}
