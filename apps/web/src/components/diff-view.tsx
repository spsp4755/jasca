'use client';

import * as React from 'react';
import { Plus, Minus, Equal, ArrowRight, AlertTriangle, Shield, CheckCircle } from 'lucide-react';
import { SeverityBadge } from '@/components/ui/badge';

// ============================================
// Types
// ============================================
export interface VulnerabilityDiff {
    cveId: string;
    title: string;
    severity: string;
    status: 'added' | 'removed' | 'unchanged';
    pkgName?: string;
    pkgVersion?: string;
}

export interface ScanDiffSummary {
    added: number;
    removed: number;
    unchanged: number;
    addedBySeverity: Record<string, number>;
    removedBySeverity: Record<string, number>;
}

// ============================================
// Diff Summary Card
// ============================================
export interface DiffSummaryCardProps {
    summary: ScanDiffSummary;
    previousScan: { date: string; imageRef: string };
    currentScan: { date: string; imageRef: string };
}

export function DiffSummaryCard({ summary, previousScan, currentScan }: DiffSummaryCardProps) {
    return (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
            {/* Scan Comparison Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                    <div className="text-center">
                        <p className="text-xs text-slate-500 dark:text-slate-400">이전 스캔</p>
                        <p className="text-sm font-medium text-slate-900 dark:text-white">{previousScan.date}</p>
                        <p className="text-xs text-slate-400 truncate max-w-[120px]" title={previousScan.imageRef}>
                            {previousScan.imageRef}
                        </p>
                    </div>
                    <ArrowRight className="h-5 w-5 text-slate-400" />
                    <div className="text-center">
                        <p className="text-xs text-slate-500 dark:text-slate-400">현재 스캔</p>
                        <p className="text-sm font-medium text-slate-900 dark:text-white">{currentScan.date}</p>
                        <p className="text-xs text-slate-400 truncate max-w-[120px]" title={currentScan.imageRef}>
                            {currentScan.imageRef}
                        </p>
                    </div>
                </div>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-4 rounded-lg bg-red-50 dark:bg-red-900/20">
                    <div className="flex items-center justify-center gap-2 mb-1">
                        <Plus className="h-4 w-4 text-red-600 dark:text-red-400" />
                        <span className="text-2xl font-bold text-red-600 dark:text-red-400 tabular-nums">
                            {summary.added}
                        </span>
                    </div>
                    <p className="text-xs text-red-600/70 dark:text-red-400/70">신규 발견</p>
                    {Object.entries(summary.addedBySeverity).length > 0 && (
                        <div className="mt-2 flex flex-wrap justify-center gap-1">
                            {Object.entries(summary.addedBySeverity).map(([severity, count]) => (
                                <span key={severity} className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                                    {severity}: {count}
                                </span>
                            ))}
                        </div>
                    )}
                </div>

                <div className="text-center p-4 rounded-lg bg-green-50 dark:bg-green-900/20">
                    <div className="flex items-center justify-center gap-2 mb-1">
                        <Minus className="h-4 w-4 text-green-600 dark:text-green-400" />
                        <span className="text-2xl font-bold text-green-600 dark:text-green-400 tabular-nums">
                            {summary.removed}
                        </span>
                    </div>
                    <p className="text-xs text-green-600/70 dark:text-green-400/70">해결됨</p>
                    {Object.entries(summary.removedBySeverity).length > 0 && (
                        <div className="mt-2 flex flex-wrap justify-center gap-1">
                            {Object.entries(summary.removedBySeverity).map(([severity, count]) => (
                                <span key={severity} className="text-[10px] px-1.5 py-0.5 rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300">
                                    {severity}: {count}
                                </span>
                            ))}
                        </div>
                    )}
                </div>

                <div className="text-center p-4 rounded-lg bg-slate-50 dark:bg-slate-700/30">
                    <div className="flex items-center justify-center gap-2 mb-1">
                        <Equal className="h-4 w-4 text-slate-600 dark:text-slate-400" />
                        <span className="text-2xl font-bold text-slate-600 dark:text-slate-400 tabular-nums">
                            {summary.unchanged}
                        </span>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">변경 없음</p>
                </div>
            </div>
        </div>
    );
}

// ============================================
// Diff List
// ============================================
export interface DiffListProps {
    vulnerabilities: VulnerabilityDiff[];
    filter?: 'all' | 'added' | 'removed';
    onItemClick?: (cveId: string) => void;
}

export function DiffList({ vulnerabilities, filter = 'all', onItemClick }: DiffListProps) {
    const filteredVulns = React.useMemo(() => {
        if (filter === 'all') return vulnerabilities;
        return vulnerabilities.filter((v) => v.status === filter);
    }, [vulnerabilities, filter]);

    if (filteredVulns.length === 0) {
        return (
            <div className="text-center py-12 text-slate-500 dark:text-slate-400">
                {filter === 'added' && '신규 발견된 취약점이 없습니다'}
                {filter === 'removed' && '해결된 취약점이 없습니다'}
                {filter === 'all' && '취약점 변경사항이 없습니다'}
            </div>
        );
    }

    return (
        <div className="divide-y divide-slate-100 dark:divide-slate-700">
            {filteredVulns.map((vuln) => (
                <DiffListItem
                    key={vuln.cveId}
                    vulnerability={vuln}
                    onClick={() => onItemClick?.(vuln.cveId)}
                />
            ))}
        </div>
    );
}

// ============================================
// Diff List Item
// ============================================
interface DiffListItemProps {
    vulnerability: VulnerabilityDiff;
    onClick?: () => void;
}

function DiffListItem({ vulnerability, onClick }: DiffListItemProps) {
    const statusConfig = {
        added: {
            icon: Plus,
            bg: 'bg-red-50 dark:bg-red-900/10',
            border: 'border-l-4 border-l-red-500',
            iconColor: 'text-red-500',
            label: '신규',
        },
        removed: {
            icon: Minus,
            bg: 'bg-green-50 dark:bg-green-900/10',
            border: 'border-l-4 border-l-green-500',
            iconColor: 'text-green-500',
            label: '해결',
        },
        unchanged: {
            icon: Equal,
            bg: '',
            border: 'border-l-4 border-l-transparent',
            iconColor: 'text-slate-400',
            label: '유지',
        },
    };

    const config = statusConfig[vulnerability.status];
    const Icon = config.icon;

    return (
        <button
            onClick={onClick}
            className={`w-full flex items-center gap-4 p-4 text-left transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50 ${config.bg} ${config.border}`}
        >
            <div className={`flex-shrink-0 ${config.iconColor}`}>
                <Icon className="h-5 w-5" />
            </div>
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium text-slate-900 dark:text-white">
                        {vulnerability.cveId}
                    </span>
                    <SeverityBadge severity={vulnerability.severity} size="sm" />
                </div>
                <p className="text-sm text-slate-500 dark:text-slate-400 truncate mt-0.5">
                    {vulnerability.title}
                </p>
                {vulnerability.pkgName && (
                    <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
                        {vulnerability.pkgName}@{vulnerability.pkgVersion}
                    </p>
                )}
            </div>
            <div className={`text-xs px-2 py-1 rounded ${vulnerability.status === 'added'
                    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                    : vulnerability.status === 'removed'
                        ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                        : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-400'
                }`}>
                {config.label}
            </div>
        </button>
    );
}

// ============================================
// Diff Filter Tabs
// ============================================
export interface DiffFilterTabsProps {
    value: 'all' | 'added' | 'removed';
    onChange: (value: 'all' | 'added' | 'removed') => void;
    counts: { all: number; added: number; removed: number };
}

export function DiffFilterTabs({ value, onChange, counts }: DiffFilterTabsProps) {
    const tabs = [
        { key: 'all' as const, label: '전체', count: counts.all },
        { key: 'added' as const, label: '신규', count: counts.added, color: 'text-red-600' },
        { key: 'removed' as const, label: '해결', count: counts.removed, color: 'text-green-600' },
    ];

    return (
        <div className="flex border-b border-slate-200 dark:border-slate-700">
            {tabs.map((tab) => (
                <button
                    key={tab.key}
                    onClick={() => onChange(tab.key)}
                    className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${value === tab.key
                            ? 'border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400'
                            : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                        }`}
                >
                    {tab.label}
                    <span className={`px-1.5 py-0.5 rounded text-xs tabular-nums ${value === tab.key
                            ? 'bg-blue-100 dark:bg-blue-900/30'
                            : 'bg-slate-100 dark:bg-slate-700'
                        } ${tab.color || ''}`}>
                        {tab.count}
                    </span>
                </button>
            ))}
        </div>
    );
}
