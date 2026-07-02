'use client';

import * as React from 'react';
import { createPortal } from 'react-dom';
import {
    Bell,
    X,
    AlertTriangle,
    Shield,
    CheckCircle,
    Clock,
    ChevronRight,
    Settings,
    Check,
} from 'lucide-react';
import { SeverityBadge } from '@/components/ui/badge';

// ============================================
// Types
// ============================================
export interface Notification {
    id: string;
    type: 'critical_vuln' | 'high_vuln' | 'policy_violation' | 'scan_completed' | 'exception_approved' | 'exception_expiring';
    title: string;
    message: string;
    timestamp: string;
    read: boolean;
    link?: string;
    metadata?: {
        cveId?: string;
        projectName?: string;
        severity?: string;
        count?: number;
    };
}

export interface GroupedNotification {
    type: Notification['type'];
    notifications: Notification[];
    latestTimestamp: string;
}

// ============================================
// Notifications Panel
// ============================================
export interface NotificationsPanelProps {
    isOpen: boolean;
    onClose: () => void;
    notifications: Notification[];
    onNotificationClick: (notification: Notification) => void;
    onMarkAllRead: () => void;
    onMarkAsRead: (id: string) => void;
}

export function NotificationsPanel({
    isOpen,
    onClose,
    notifications,
    onNotificationClick,
    onMarkAllRead,
    onMarkAsRead,
}: NotificationsPanelProps) {
    const [mounted, setMounted] = React.useState(false);

    React.useEffect(() => {
        setMounted(true);
    }, []);

    // Group similar notifications
    const groupedNotifications = React.useMemo(() => {
        const groups: Map<string, GroupedNotification> = new Map();

        notifications.forEach((notification) => {
            const key = `${notification.type}-${notification.metadata?.severity || ''}`;
            const existing = groups.get(key);

            if (existing) {
                existing.notifications.push(notification);
                if (new Date(notification.timestamp) > new Date(existing.latestTimestamp)) {
                    existing.latestTimestamp = notification.timestamp;
                }
            } else {
                groups.set(key, {
                    type: notification.type,
                    notifications: [notification],
                    latestTimestamp: notification.timestamp,
                });
            }
        });

        return Array.from(groups.values()).sort(
            (a, b) => new Date(b.latestTimestamp).getTime() - new Date(a.latestTimestamp).getTime()
        );
    }, [notifications]);

    const unreadCount = notifications.filter((n) => !n.read).length;

    if (!mounted || !isOpen) return null;

    return createPortal(
        <>
            {/* Backdrop */}
            <div
                className="fixed inset-0 z-40"
                onClick={onClose}
            />

            {/* Panel */}
            <div className="fixed top-16 right-4 z-50 w-96 max-h-[calc(100vh-100px)] bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-slate-200 dark:border-slate-700 flex flex-col animate-in slide-in-from-top-2 fade-in duration-200">
                {/* Header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-700">
                    <div className="flex items-center gap-2">
                        <Bell className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                        <h3 className="font-semibold text-slate-900 dark:text-white">알림</h3>
                        {unreadCount > 0 && (
                            <span className="px-1.5 py-0.5 text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 rounded-full">
                                {unreadCount}
                            </span>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        {unreadCount > 0 && (
                            <button
                                onClick={onMarkAllRead}
                                className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                            >
                                모두 읽음
                            </button>
                        )}
                        <button
                            onClick={onClose}
                            className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-700"
                        >
                            <X className="h-4 w-4 text-slate-500" />
                        </button>
                    </div>
                </div>

                {/* Notifications List */}
                <div className="flex-1 overflow-y-auto">
                    {notifications.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-slate-500 dark:text-slate-400">
                            <Bell className="h-12 w-12 mb-3 opacity-50" />
                            <p>새로운 알림이 없습니다</p>
                        </div>
                    ) : (
                        <div className="divide-y divide-slate-100 dark:divide-slate-700">
                            {groupedNotifications.map((group) => (
                                <GroupedNotificationItem
                                    key={`${group.type}-${group.latestTimestamp}`}
                                    group={group}
                                    onClick={onNotificationClick}
                                    onMarkAsRead={onMarkAsRead}
                                />
                            ))}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
                    <a
                        href="/dashboard/notifications"
                        className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                    >
                        모든 알림 보기
                    </a>
                    <a
                        href="/dashboard/settings"
                        className="flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                    >
                        <Settings className="h-4 w-4" />
                        설정
                    </a>
                </div>
            </div>
        </>,
        document.body
    );
}

// ============================================
// Grouped Notification Item
// ============================================
interface GroupedNotificationItemProps {
    group: GroupedNotification;
    onClick: (notification: Notification) => void;
    onMarkAsRead: (id: string) => void;
}

function GroupedNotificationItem({ group, onClick, onMarkAsRead }: GroupedNotificationItemProps) {
    const latest = group.notifications[0];
    const count = group.notifications.length;
    const hasUnread = group.notifications.some((n) => !n.read);
    const config = getNotificationConfig(latest.type);
    const Icon = config.icon;

    const relativeTime = getRelativeTime(group.latestTimestamp);

    const handleClick = () => {
        // Mark all in group as read
        group.notifications.forEach((n) => {
            if (!n.read) onMarkAsRead(n.id);
        });
        onClick(latest);
    };

    return (
        <button
            onClick={handleClick}
            className={`w-full flex items-start gap-3 p-4 text-left transition-colors hover:bg-slate-50 dark:hover:bg-slate-700/50 ${hasUnread ? 'bg-blue-50/50 dark:bg-blue-900/10' : ''
                }`}
        >
            <div className={`flex-shrink-0 p-2 rounded-lg ${config.bg}`}>
                <Icon className={`h-4 w-4 ${config.iconColor}`} />
            </div>
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                        {count > 1 ? `${config.groupTitle} (${count}건)` : latest.title}
                    </p>
                    {hasUnread && (
                        <span className="w-2 h-2 rounded-full bg-blue-600 flex-shrink-0" />
                    )}
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 line-clamp-2">
                    {count > 1
                        ? `${latest.metadata?.projectName || '여러 프로젝트'}에서 ${count}개의 알림`
                        : latest.message
                    }
                </p>
                <p className="text-xs text-slate-400 mt-1">{relativeTime}</p>
            </div>
            <ChevronRight className="h-4 w-4 text-slate-400 flex-shrink-0 mt-1" />
        </button>
    );
}

// ============================================
// Notification Bell Button
// ============================================
export interface NotificationBellProps {
    unreadCount: number;
    onClick: () => void;
}

export function NotificationBell({ unreadCount, onClick }: NotificationBellProps) {
    return (
        <button
            onClick={onClick}
            className="relative p-2 rounded-lg text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700 transition-colors"
            aria-label={`알림 ${unreadCount > 0 ? `(${unreadCount}개 읽지 않음)` : ''}`}
        >
            <Bell className="h-5 w-5" />
            {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-bold text-white bg-red-500 rounded-full">
                    {unreadCount > 99 ? '99+' : unreadCount}
                </span>
            )}
        </button>
    );
}

// ============================================
// Helpers
// ============================================
interface NotificationConfig {
    icon: React.ComponentType<{ className?: string }>;
    bg: string;
    iconColor: string;
    groupTitle: string;
}

function getNotificationConfig(type: Notification['type']): NotificationConfig {
    const configs: Record<Notification['type'], NotificationConfig> = {
        critical_vuln: {
            icon: Shield,
            bg: 'bg-red-100 dark:bg-red-900/30',
            iconColor: 'text-red-600 dark:text-red-400',
            groupTitle: 'Critical 취약점 발견',
        },
        high_vuln: {
            icon: AlertTriangle,
            bg: 'bg-orange-100 dark:bg-orange-900/30',
            iconColor: 'text-orange-600 dark:text-orange-400',
            groupTitle: 'High 취약점 발견',
        },
        policy_violation: {
            icon: AlertTriangle,
            bg: 'bg-amber-100 dark:bg-amber-900/30',
            iconColor: 'text-amber-600 dark:text-amber-400',
            groupTitle: '정책 위반 감지',
        },
        scan_completed: {
            icon: CheckCircle,
            bg: 'bg-green-100 dark:bg-green-900/30',
            iconColor: 'text-green-600 dark:text-green-400',
            groupTitle: '스캔 완료',
        },
        exception_approved: {
            icon: Check,
            bg: 'bg-blue-100 dark:bg-blue-900/30',
            iconColor: 'text-blue-600 dark:text-blue-400',
            groupTitle: '예외 승인됨',
        },
        exception_expiring: {
            icon: Clock,
            bg: 'bg-purple-100 dark:bg-purple-900/30',
            iconColor: 'text-purple-600 dark:text-purple-400',
            groupTitle: '예외 만료 예정',
        },
    };

    return configs[type];
}

function getRelativeTime(timestamp: string): string {
    const now = new Date();
    const date = new Date(timestamp);
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return '방금 전';
    if (diffMins < 60) return `${diffMins}분 전`;
    if (diffHours < 24) return `${diffHours}시간 전`;
    if (diffDays < 7) return `${diffDays}일 전`;

    return date.toLocaleDateString('ko-KR', { month: 'short', day: 'numeric' });
}
