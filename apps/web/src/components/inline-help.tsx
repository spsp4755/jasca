'use client';

import * as React from 'react';
import { HelpCircle, ExternalLink, X, Book, Lightbulb } from 'lucide-react';
import { Tooltip } from '@/components/ui/tooltip';

// ============================================
// Inline Help (인라인 도움말)
// ============================================
export interface InlineHelpProps {
    content: string;
    title?: string;
    link?: {
        href: string;
        label: string;
    };
    size?: 'sm' | 'md';
}

export function InlineHelp({ content, title, link, size = 'md' }: InlineHelpProps) {
    const sizeClasses = size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4';

    const tooltipContent = (
        <div className="max-w-[240px]">
            {title && (
                <p className="font-medium text-slate-900 dark:text-white mb-1">{title}</p>
            )}
            <p className="text-slate-600 dark:text-slate-400 text-sm">{content}</p>
            {link && (
                <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 mt-2 text-xs text-blue-600 dark:text-blue-400 hover:underline"
                    onClick={(e) => e.stopPropagation()}
                >
                    {link.label}
                    <ExternalLink className="h-3 w-3" />
                </a>
            )}
        </div>
    );

    return (
        <Tooltip content={tooltipContent} position="top" delay={100}>
            <button
                type="button"
                className="inline-flex items-center justify-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded"
                aria-label="도움말"
            >
                <HelpCircle className={sizeClasses} />
            </button>
        </Tooltip>
    );
}

// ============================================
// Help Panel (접이식 도움말 패널)
// ============================================
export interface HelpPanelProps {
    title: string;
    children: React.ReactNode;
    defaultOpen?: boolean;
    icon?: React.ReactNode;
}

export function HelpPanel({ title, children, defaultOpen = false, icon }: HelpPanelProps) {
    const [isOpen, setIsOpen] = React.useState(defaultOpen);

    return (
        <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="w-full flex items-center gap-2 px-4 py-3 text-left"
            >
                {icon || <Lightbulb className="h-4 w-4 text-blue-600 dark:text-blue-400" />}
                <span className="font-medium text-blue-900 dark:text-blue-100 flex-1">
                    {title}
                </span>
                <span className={`transition-transform ${isOpen ? 'rotate-180' : ''}`}>
                    <svg className="h-4 w-4 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                </span>
            </button>
            {isOpen && (
                <div className="px-4 pb-4 text-sm text-blue-800 dark:text-blue-200">
                    {children}
                </div>
            )}
        </div>
    );
}

// ============================================
// Contextual Tips (컨텍스트별 팁)
// ============================================
export interface ContextualTipProps {
    id: string;
    children: React.ReactNode;
    dismissible?: boolean;
    variant?: 'info' | 'tip' | 'warning';
}

export function ContextualTip({ id, children, dismissible = true, variant = 'tip' }: ContextualTipProps) {
    const [dismissed, setDismissed] = React.useState(false);

    React.useEffect(() => {
        try {
            const dismissedTips = JSON.parse(localStorage.getItem('jasca_dismissed_tips') || '[]');
            if (dismissedTips.includes(id)) {
                setDismissed(true);
            }
        } catch { }
    }, [id]);

    const handleDismiss = () => {
        setDismissed(true);
        try {
            const dismissedTips = JSON.parse(localStorage.getItem('jasca_dismissed_tips') || '[]');
            if (!dismissedTips.includes(id)) {
                localStorage.setItem('jasca_dismissed_tips', JSON.stringify([...dismissedTips, id]));
            }
        } catch { }
    };

    if (dismissed) return null;

    const variantStyles = {
        info: 'bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800 text-blue-800 dark:text-blue-200',
        tip: 'bg-amber-50 border-amber-200 dark:bg-amber-900/20 dark:border-amber-800 text-amber-800 dark:text-amber-200',
        warning: 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800 text-red-800 dark:text-red-200',
    };

    const iconStyles = {
        info: 'text-blue-600 dark:text-blue-400',
        tip: 'text-amber-600 dark:text-amber-400',
        warning: 'text-red-600 dark:text-red-400',
    };

    return (
        <div className={`flex items-start gap-3 p-4 rounded-lg border ${variantStyles[variant]}`}>
            <Lightbulb className={`h-5 w-5 flex-shrink-0 ${iconStyles[variant]}`} />
            <div className="flex-1 text-sm">{children}</div>
            {dismissible && (
                <button
                    onClick={handleDismiss}
                    className="p-1 rounded hover:bg-white/50 dark:hover:bg-black/20 transition-colors"
                    aria-label="닫기"
                >
                    <X className="h-4 w-4" />
                </button>
            )}
        </div>
    );
}

// ============================================
// Documentation Link
// ============================================
export interface DocLinkProps {
    href: string;
    children: React.ReactNode;
}

export function DocLink({ href, children }: DocLinkProps) {
    return (
        <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-sm text-blue-600 dark:text-blue-400 hover:underline"
        >
            <Book className="h-4 w-4" />
            {children}
            <ExternalLink className="h-3 w-3" />
        </a>
    );
}

// ============================================
// Empty State with Help
// ============================================
export interface EmptyStateWithHelpProps {
    icon?: React.ReactNode;
    title: string;
    description: string;
    action?: {
        label: string;
        onClick: () => void;
    };
    helpLink?: {
        href: string;
        label: string;
    };
}

export function EmptyStateWithHelp({ icon, title, description, action, helpLink }: EmptyStateWithHelpProps) {
    return (
        <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
            {icon && (
                <div className="mb-4 p-4 rounded-full bg-slate-100 dark:bg-slate-800">
                    {icon}
                </div>
            )}
            <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                {title}
            </h3>
            <p className="text-slate-500 dark:text-slate-400 mb-6 max-w-md">
                {description}
            </p>
            {action && (
                <button
                    onClick={action.onClick}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                >
                    {action.label}
                </button>
            )}
            {helpLink && (
                <div className="mt-4">
                    <DocLink href={helpLink.href}>{helpLink.label}</DocLink>
                </div>
            )}
        </div>
    );
}
