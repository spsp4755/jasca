'use client';

import * as React from 'react';
import {
    AlertTriangle,
    CheckCircle,
    Clock,
    Eye,
    GitBranch,
    MessageSquare,
    RotateCcw,
    User,
    FileText,
    Link as LinkIcon,
} from 'lucide-react';
import { StatusDisplay, type VulnStatus } from '@/components/status-dropdown';

// ============================================
// Types
// ============================================
export interface TimelineEvent {
    id: string;
    type: 'discovered' | 'assigned' | 'status_changed' | 'comment' | 'fix_submitted' | 'verified' | 'reopened' | 'evidence_added';
    timestamp: string;
    user?: {
        name: string;
        avatar?: string;
    };
    data?: {
        fromStatus?: VulnStatus;
        toStatus?: VulnStatus;
        comment?: string;
        prUrl?: string;
        assigneeName?: string;
    };
}

// ============================================
// Timeline Component
// ============================================
export interface TimelineProps {
    events: TimelineEvent[];
    className?: string;
}

export function Timeline({ events, className }: TimelineProps) {
    if (events.length === 0) {
        return (
            <div className="text-center py-12 text-slate-500 dark:text-slate-400">
                타임라인 이벤트가 없습니다
            </div>
        );
    }

    return (
        <div className={`relative ${className || ''}`}>
            {/* Vertical line */}
            <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-slate-200 dark:bg-slate-700" />

            <div className="space-y-4">
                {events.map((event, index) => (
                    <TimelineItem
                        key={event.id}
                        event={event}
                        isFirst={index === 0}
                        isLast={index === events.length - 1}
                    />
                ))}
            </div>
        </div>
    );
}

// ============================================
// Timeline Item
// ============================================
interface TimelineItemProps {
    event: TimelineEvent;
    isFirst: boolean;
    isLast: boolean;
}

function TimelineItem({ event, isFirst, isLast }: TimelineItemProps) {
    const config = getEventConfig(event.type);
    const Icon = config.icon;

    const formattedDate = new Date(event.timestamp).toLocaleString('ko-KR', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });

    return (
        <div className="relative flex gap-4 pl-0">
            {/* Icon */}
            <div className={`relative z-10 flex items-center justify-center w-8 h-8 rounded-full ${config.bg} ${config.iconColor} ring-4 ring-white dark:ring-slate-900`}>
                <Icon className="h-4 w-4" />
            </div>

            {/* Content */}
            <div className={`flex-1 pb-4 ${isLast ? '' : ''}`}>
                <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                            {event.user && (
                                <span className="font-medium text-slate-900 dark:text-white text-sm">
                                    {event.user.name}
                                </span>
                            )}
                            <span className="text-slate-600 dark:text-slate-400 text-sm">
                                {config.getDescription(event)}
                            </span>
                        </div>

                        {/* Additional data rendering */}
                        {event.type === 'status_changed' && event.data?.fromStatus && event.data?.toStatus && (
                            <div className="flex items-center gap-2 mt-2">
                                <StatusDisplay status={event.data.fromStatus} size="sm" />
                                <span className="text-slate-400">→</span>
                                <StatusDisplay status={event.data.toStatus} size="sm" />
                            </div>
                        )}

                        {event.type === 'comment' && event.data?.comment && (
                            <div className="mt-2 p-3 bg-slate-50 dark:bg-slate-800 rounded-lg text-sm text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                {event.data.comment}
                            </div>
                        )}

                        {event.type === 'fix_submitted' && event.data?.prUrl && (
                            <a
                                href={event.data.prUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1.5 mt-2 text-sm text-blue-600 dark:text-blue-400 hover:underline"
                            >
                                <LinkIcon className="h-3 w-3" />
                                PR 링크 보기
                            </a>
                        )}
                    </div>

                    <time className="text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                        {formattedDate}
                    </time>
                </div>
            </div>
        </div>
    );
}

// ============================================
// Event Configuration
// ============================================
interface EventConfig {
    icon: React.ComponentType<{ className?: string }>;
    bg: string;
    iconColor: string;
    getDescription: (event: TimelineEvent) => string;
}

function getEventConfig(type: TimelineEvent['type']): EventConfig {
    const configs: Record<TimelineEvent['type'], EventConfig> = {
        discovered: {
            icon: AlertTriangle,
            bg: 'bg-red-100 dark:bg-red-900/30',
            iconColor: 'text-red-600 dark:text-red-400',
            getDescription: () => '취약점이 발견되었습니다',
        },
        assigned: {
            icon: User,
            bg: 'bg-purple-100 dark:bg-purple-900/30',
            iconColor: 'text-purple-600 dark:text-purple-400',
            getDescription: (e) => `${e.data?.assigneeName || '담당자'}에게 할당되었습니다`,
        },
        status_changed: {
            icon: Clock,
            bg: 'bg-blue-100 dark:bg-blue-900/30',
            iconColor: 'text-blue-600 dark:text-blue-400',
            getDescription: () => '상태를 변경했습니다',
        },
        comment: {
            icon: MessageSquare,
            bg: 'bg-slate-100 dark:bg-slate-700',
            iconColor: 'text-slate-600 dark:text-slate-400',
            getDescription: () => '코멘트를 남겼습니다',
        },
        fix_submitted: {
            icon: GitBranch,
            bg: 'bg-cyan-100 dark:bg-cyan-900/30',
            iconColor: 'text-cyan-600 dark:text-cyan-400',
            getDescription: () => '수정 사항을 제출했습니다',
        },
        verified: {
            icon: CheckCircle,
            bg: 'bg-green-100 dark:bg-green-900/30',
            iconColor: 'text-green-600 dark:text-green-400',
            getDescription: () => '수정이 검증되었습니다',
        },
        reopened: {
            icon: RotateCcw,
            bg: 'bg-amber-100 dark:bg-amber-900/30',
            iconColor: 'text-amber-600 dark:text-amber-400',
            getDescription: () => '취약점이 재발생했습니다',
        },
        evidence_added: {
            icon: FileText,
            bg: 'bg-indigo-100 dark:bg-indigo-900/30',
            iconColor: 'text-indigo-600 dark:text-indigo-400',
            getDescription: () => '증거 자료를 첨부했습니다',
        },
    };

    return configs[type];
}

// ============================================
// Compact Timeline (요약용)
// ============================================
export interface CompactTimelineProps {
    events: TimelineEvent[];
    maxItems?: number;
    onViewAll?: () => void;
}

export function CompactTimeline({ events, maxItems = 5, onViewAll }: CompactTimelineProps) {
    const displayEvents = events.slice(0, maxItems);
    const hasMore = events.length > maxItems;

    return (
        <div className="space-y-3">
            {displayEvents.map((event) => {
                const config = getEventConfig(event.type);
                const Icon = config.icon;
                const formattedDate = new Date(event.timestamp).toLocaleDateString('ko-KR', {
                    month: 'short',
                    day: 'numeric',
                });

                return (
                    <div key={event.id} className="flex items-center gap-3">
                        <div className={`flex items-center justify-center w-6 h-6 rounded-full ${config.bg} ${config.iconColor}`}>
                            <Icon className="h-3 w-3" />
                        </div>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm text-slate-600 dark:text-slate-400 truncate">
                                {config.getDescription(event)}
                            </p>
                        </div>
                        <time className="text-xs text-slate-400">{formattedDate}</time>
                    </div>
                );
            })}

            {hasMore && onViewAll && (
                <button
                    onClick={onViewAll}
                    className="w-full text-center text-sm text-blue-600 dark:text-blue-400 hover:underline py-2"
                >
                    전체 타임라인 보기 ({events.length}개 이벤트)
                </button>
            )}
        </div>
    );
}
