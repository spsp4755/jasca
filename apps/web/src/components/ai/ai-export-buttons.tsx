'use client';

import { useState } from 'react';
import { FileDown, Loader2 } from 'lucide-react';
import { downloadWithAuth } from '@/lib/api/fetch-utils';

type AiExportFormat = 'pdf' | 'docx';

export interface AiExportButtonsProps {
    executionId: string;
    compact?: boolean;
    className?: string;
}

export function AiExportButtons({
    executionId,
    compact = false,
    className = '',
}: AiExportButtonsProps) {
    const [downloading, setDownloading] = useState<AiExportFormat | null>(null);
    const [error, setError] = useState<string | null>(null);

    const download = async (format: AiExportFormat) => {
        setDownloading(format);
        setError(null);
        try {
            await downloadWithAuth(
                `/api/ai/history/${encodeURIComponent(executionId)}/export?format=${format}`,
                `ai-report.${format}`,
            );
        } catch (downloadError) {
            console.error('AI report download failed:', downloadError);
            setError('AI 보고서를 다운로드하지 못했습니다.');
        } finally {
            setDownloading(null);
        }
    };

    return (
        <div
            className={`inline-flex items-center gap-1 ${className}`}
            title={error || 'AI 분석 보고서 다운로드'}
        >
            {(['pdf', 'docx'] as const).map(format => (
                <button
                    key={format}
                    type="button"
                    onClick={() => download(format)}
                    disabled={downloading !== null}
                    aria-label={`${format.toUpperCase()} 보고서 다운로드`}
                    className={`inline-flex items-center gap-1.5 rounded-lg border border-slate-200 text-slate-600 transition-colors hover:border-blue-300 hover:bg-blue-50 hover:text-blue-700 disabled:cursor-wait disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:border-blue-700 dark:hover:bg-blue-950/30 dark:hover:text-blue-300 ${
                        compact ? 'px-2 py-1.5 text-xs' : 'px-3 py-2 text-sm'
                    }`}
                >
                    {downloading === format ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                        <FileDown className="h-3.5 w-3.5" />
                    )}
                    {format.toUpperCase()}
                </button>
            ))}
            {error && <span className="sr-only" role="alert">{error}</span>}
        </div>
    );
}
