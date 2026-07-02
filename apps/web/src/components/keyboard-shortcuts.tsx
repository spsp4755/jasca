'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { Command, X } from 'lucide-react';
import { createPortal } from 'react-dom';

// ============================================
// Types
// ============================================
export interface KeyboardShortcut {
    key: string;
    modifiers?: ('ctrl' | 'alt' | 'shift' | 'meta')[];
    description: string;
    action?: () => void;
    href?: string;
    scope?: 'global' | 'dashboard' | 'detail' | 'modal';
}

// ============================================
// Default Shortcuts
// ============================================
const defaultShortcuts: KeyboardShortcut[] = [
    // Navigation
    { key: 'g', modifiers: ['ctrl'], description: '대시보드로 이동', href: '/dashboard', scope: 'global' },
    { key: 'p', modifiers: ['ctrl'], description: '프로젝트 목록', href: '/dashboard/projects', scope: 'global' },
    { key: 'v', modifiers: ['ctrl'], description: '취약점 목록', href: '/dashboard/vulnerabilities', scope: 'global' },
    { key: 's', modifiers: ['ctrl', 'shift'], description: '설정', href: '/dashboard/settings', scope: 'global' },

    // Actions
    { key: 'k', modifiers: ['ctrl'], description: '빠른 검색 열기', scope: 'global' },
    { key: '/', description: '검색에 포커스', scope: 'global' },
    { key: 'Escape', description: '모달/패널 닫기', scope: 'modal' },

    // Table/List
    { key: 'j', description: '다음 항목', scope: 'dashboard' },
    { key: 'k', description: '이전 항목', scope: 'dashboard' },
    { key: 'Enter', description: '선택한 항목 열기', scope: 'dashboard' },

    // Detail Page
    { key: 'e', description: '상태 변경', scope: 'detail' },
    { key: 'a', description: '담당자 할당', scope: 'detail' },
    { key: 'c', description: '코멘트 추가', scope: 'detail' },
];

// ============================================
// Keyboard Shortcuts Provider
// ============================================
interface KeyboardShortcutsContextType {
    registerShortcut: (shortcut: KeyboardShortcut) => () => void;
    unregisterShortcut: (key: string, modifiers?: string[]) => void;
    openShortcutsDialog: () => void;
    closeShortcutsDialog: () => void;
}

const KeyboardShortcutsContext = React.createContext<KeyboardShortcutsContextType | null>(null);

export function KeyboardShortcutsProvider({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const [shortcuts, setShortcuts] = React.useState<KeyboardShortcut[]>(defaultShortcuts);
    const [isDialogOpen, setIsDialogOpen] = React.useState(false);

    // Handle keyboard events
    React.useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            // Don't trigger shortcuts when typing in inputs
            if (
                e.target instanceof HTMLInputElement ||
                e.target instanceof HTMLTextAreaElement ||
                (e.target as HTMLElement)?.isContentEditable
            ) {
                // Only Escape is allowed to work in inputs
                if (e.key !== 'Escape') return;
            }

            // Find matching shortcut
            const matchingShortcut = shortcuts.find((s) => {
                const keyMatch = s.key.toLowerCase() === e.key.toLowerCase();
                const ctrlMatch = (s.modifiers?.includes('ctrl') ?? false) === (e.ctrlKey || e.metaKey);
                const altMatch = (s.modifiers?.includes('alt') ?? false) === e.altKey;
                const shiftMatch = (s.modifiers?.includes('shift') ?? false) === e.shiftKey;

                return keyMatch && ctrlMatch && altMatch && shiftMatch;
            });

            if (matchingShortcut) {
                // Prevent default browser behavior
                if (matchingShortcut.modifiers?.length || matchingShortcut.key === '/') {
                    e.preventDefault();
                }

                // Execute action or navigate
                if (matchingShortcut.action) {
                    matchingShortcut.action();
                } else if (matchingShortcut.href) {
                    router.push(matchingShortcut.href);
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [shortcuts, router]);

    // Register shortcut
    const registerShortcut = React.useCallback((shortcut: KeyboardShortcut) => {
        setShortcuts((prev) => [...prev, shortcut]);
        return () => {
            setShortcuts((prev) =>
                prev.filter((s) => !(s.key === shortcut.key && JSON.stringify(s.modifiers) === JSON.stringify(shortcut.modifiers)))
            );
        };
    }, []);

    // Unregister shortcut
    const unregisterShortcut = React.useCallback((key: string, modifiers?: string[]) => {
        setShortcuts((prev) =>
            prev.filter((s) => !(s.key === key && JSON.stringify(s.modifiers) === JSON.stringify(modifiers)))
        );
    }, []);

    const value = React.useMemo(() => ({
        registerShortcut,
        unregisterShortcut,
        openShortcutsDialog: () => setIsDialogOpen(true),
        closeShortcutsDialog: () => setIsDialogOpen(false),
    }), [registerShortcut, unregisterShortcut]);

    return (
        <KeyboardShortcutsContext.Provider value={value}>
            {children}
            <ShortcutsDialog
                isOpen={isDialogOpen}
                onClose={() => setIsDialogOpen(false)}
                shortcuts={shortcuts}
            />
        </KeyboardShortcutsContext.Provider>
    );
}

export function useKeyboardShortcuts() {
    const context = React.useContext(KeyboardShortcutsContext);
    if (!context) {
        throw new Error('useKeyboardShortcuts must be used within KeyboardShortcutsProvider');
    }
    return context;
}

// ============================================
// Shortcuts Dialog
// ============================================
interface ShortcutsDialogProps {
    isOpen: boolean;
    onClose: () => void;
    shortcuts: KeyboardShortcut[];
}

function ShortcutsDialog({ isOpen, onClose, shortcuts }: ShortcutsDialogProps) {
    const [mounted, setMounted] = React.useState(false);

    React.useEffect(() => {
        setMounted(true);
    }, []);

    React.useEffect(() => {
        const handleEscape = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && isOpen) {
                onClose();
            }
        };
        window.addEventListener('keydown', handleEscape);
        return () => window.removeEventListener('keydown', handleEscape);
    }, [isOpen, onClose]);

    if (!mounted || !isOpen) return null;

    const groupedShortcuts = shortcuts.reduce((acc, shortcut) => {
        const scope = shortcut.scope || 'global';
        if (!acc[scope]) acc[scope] = [];
        acc[scope].push(shortcut);
        return acc;
    }, {} as Record<string, KeyboardShortcut[]>);

    const scopeLabels: Record<string, string> = {
        global: '전역',
        dashboard: '대시보드',
        detail: '상세 페이지',
        modal: '모달/패널',
    };

    return createPortal(
        <>
            {/* Backdrop */}
            <div
                className="fixed inset-0 z-50 bg-black/50"
                onClick={onClose}
            />

            {/* Dialog */}
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                <div
                    className="bg-white dark:bg-slate-800 rounded-xl shadow-xl max-w-lg w-full max-h-[80vh] overflow-hidden animate-in zoom-in-95 fade-in duration-200"
                    onClick={(e) => e.stopPropagation()}
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                        <div className="flex items-center gap-2">
                            <Command className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                            <h2 className="font-semibold text-slate-900 dark:text-white">키보드 단축키</h2>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-700"
                        >
                            <X className="h-5 w-5 text-slate-500" />
                        </button>
                    </div>

                    {/* Content */}
                    <div className="px-6 py-4 overflow-y-auto max-h-[60vh] space-y-6">
                        {Object.entries(groupedShortcuts).map(([scope, scopeShortcuts]) => (
                            <div key={scope}>
                                <h3 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">
                                    {scopeLabels[scope] || scope}
                                </h3>
                                <div className="space-y-2">
                                    {scopeShortcuts.map((shortcut) => (
                                        <div
                                            key={`${shortcut.key}-${shortcut.modifiers?.join('-')}`}
                                            className="flex items-center justify-between"
                                        >
                                            <span className="text-sm text-slate-600 dark:text-slate-300">
                                                {shortcut.description}
                                            </span>
                                            <ShortcutKey shortcut={shortcut} />
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Footer */}
                    <div className="px-6 py-3 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700">
                        <p className="text-xs text-slate-500 dark:text-slate-400 text-center">
                            <kbd className="keyboard-key">?</kbd> 를 눌러 이 창을 열 수 있습니다
                        </p>
                    </div>
                </div>
            </div>
        </>,
        document.body
    );
}

// ============================================
// Shortcut Key Display
// ============================================
interface ShortcutKeyProps {
    shortcut: KeyboardShortcut;
}

function ShortcutKey({ shortcut }: ShortcutKeyProps) {
    const keys: string[] = [];

    if (shortcut.modifiers?.includes('ctrl') || shortcut.modifiers?.includes('meta')) {
        keys.push('⌘');
    }
    if (shortcut.modifiers?.includes('alt')) {
        keys.push('⌥');
    }
    if (shortcut.modifiers?.includes('shift')) {
        keys.push('⇧');
    }
    keys.push(shortcut.key.length === 1 ? shortcut.key.toUpperCase() : shortcut.key);

    return (
        <div className="flex items-center gap-1">
            {keys.map((key, index) => (
                <kbd
                    key={index}
                    className="px-2 py-1 text-xs font-mono bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded border border-slate-200 dark:border-slate-600"
                >
                    {key}
                </kbd>
            ))}
        </div>
    );
}

// ============================================
// Shortcut Hint (인라인 힌트)
// ============================================
export interface ShortcutHintProps {
    keys: string[];
    className?: string;
}

export function ShortcutHint({ keys, className }: ShortcutHintProps) {
    return (
        <span className={`inline-flex items-center gap-0.5 ${className || ''}`}>
            {keys.map((key, index) => (
                <kbd
                    key={index}
                    className="px-1.5 py-0.5 text-[10px] font-mono bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 rounded"
                >
                    {key}
                </kbd>
            ))}
        </span>
    );
}
