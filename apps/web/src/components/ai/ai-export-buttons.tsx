'use client';

import { useState } from 'react';
import { CheckCircle2, FileDown, Loader2, RefreshCw } from 'lucide-react';
import { downloadWithAuth } from '@/lib/api/fetch-utils';
import { buildAiExportUrl } from '@/lib/ai-job-utils';

type AiExportFormat = 'pdf' | 'docx';
type AiExportScope = 'summary' | 'full';

export interface AiExportButtonsProps {
    executionId: string;
    compact?: boolean;
    className?: string;
}

export function AiExportButtons({ executionId, compact = false, className = '' }: AiExportButtonsProps) {
    const [scope, setScope] = useState<AiExportScope>('summary');
    const [downloading, setDownloading] = useState<AiExportFormat | null>(null);
    const [lastFormat, setLastFormat] = useState<AiExportFormat | null>(null);
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const download = async (format: AiExportFormat) => {
        if (scope === 'full' && !window.confirm('전체 결과가 포함된 보고서를 생성합니다. 데이터가 많으면 시간이 걸릴 수 있습니다. 계속할까요?')) {
            return;
        }

        setDownloading(format);
        setLastFormat(format);
        setMessage(null);
        try {
            const fileName = await downloadWithAuth(
                buildAiExportUrl(executionId, format, scope),
                `JASCA-AI-report.${format}`,
            );
            setMessage({ type: 'success', text: `${fileName} 다운로드를 시작했습니다.` });
        } catch (error) {
            console.error('AI report download failed:', error);
            setMessage({
                type: 'error',
                text: error instanceof Error ? error.message : 'AI 보고서를 다운로드하지 못했습니다.',
            });
        } finally {
            setDownloading(null);
        }
    };

    return (
        <div className={`flex flex-wrap items-center gap-2 ${className}`}>
            <label className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
                <span className="sr-only">보고서 범위</span>
                <select
                    value={scope}
                    onChange={event => setScope(event.target.value as AiExportScope)}
                    disabled={downloading !== null}
                    className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 dark:border-slate-700 dark:bg-slate-900"
                >
                    <option value="summary">요약 보고서 (상위 20개)</option>
                    <option value="full">전체 보고서</option>
                </select>
            </label>
            {(['pdf', 'docx'] as const).map(format => (
                <button
                    key={format}
                    type="button"
                    onClick={() => void download(format)}
                    disabled={downloading !== null}
                    aria-label={`${format.toUpperCase()} 보고서 다운로드`}
                    className={`inline-flex items-center gap-1.5 rounded-lg border border-slate-200 text-slate-600 transition-colors hover:border-blue-300 hover:bg-blue-50 hover:text-blue-700 disabled:cursor-wait disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 ${compact ? 'px-2 py-1.5 text-xs' : 'px-3 py-2 text-sm'}`}
                >
                    {downloading === format ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileDown className="h-3.5 w-3.5" />}
                    {format.toUpperCase()}
                </button>
            ))}
            {message && (
                <span
                    role={message.type === 'error' ? 'alert' : 'status'}
                    className={`inline-flex items-center gap-1 text-xs ${message.type === 'error' ? 'text-red-600' : 'text-emerald-600'}`}
                >
                    {message.type === 'success' && <CheckCircle2 className="h-3.5 w-3.5" />}
                    {message.text}
                    {message.type === 'error' && lastFormat && (
                        <button type="button" onClick={() => void download(lastFormat)} className="inline-flex items-center gap-1 underline">
                            <RefreshCw className="h-3 w-3" /> 재시도
                        </button>
                    )}
                </span>
            )}
        </div>
    );
}
