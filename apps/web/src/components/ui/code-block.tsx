'use client';

import { useState, useCallback, useRef, useEffect } from 'react';
import { Copy, Check, Terminal, FileCode, FileJson } from 'lucide-react';

export interface CodeBlockProps {
    code: string;
    language?: 'bash' | 'yaml' | 'json' | 'shell' | 'typescript';
    title?: string;
    showLineNumbers?: boolean;
    highlightLines?: number[];
    className?: string;
}

const languageIcons: Record<string, React.ComponentType<{ className?: string }>> = {
    bash: Terminal,
    shell: Terminal,
    yaml: FileCode,
    json: FileJson,
    typescript: FileCode,
};

const languageLabels: Record<string, string> = {
    bash: 'Bash',
    shell: 'Shell',
    yaml: 'YAML',
    json: 'JSON',
    typescript: 'TypeScript',
};

// Escape HTML entities
function escapeHtml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Simple syntax highlighting (apply after HTML escaping)
function highlightCode(code: string, language: string): string {
    // First escape HTML entities
    let escaped = escapeHtml(code);

    if (language === 'bash' || language === 'shell') {
        return escaped
            .replace(/(#.*$)/gm, '<span class="code-comment">$1</span>')
            .replace(/(\$\w+|\$\{[^}]+\})/g, '<span class="code-variable">$1</span>')
            .replace(/\b(trivy|curl|docker|cat|echo|export|pipe|for|do|done|if|then|fi|sleep|break)\b/g, '<span class="code-keyword">$1</span>')
            .replace(/(--[\w-]+)/g, '<span class="code-flag">$1</span>')
            .replace(/(&quot;(?:[^&]|&(?!quot;))*&quot;)/g, '<span class="code-string">$1</span>');
    }
    if (language === 'yaml') {
        return escaped
            .replace(/(#.*$)/gm, '<span class="code-comment">$1</span>')
            .replace(/^(\s*[\w-]+):/gm, '<span class="code-key">$1</span>:')
            .replace(/(&quot;(?:[^&]|&(?!quot;))*&quot;|&#039;(?:[^&]|&(?!#039;))*&#039;)/g, '<span class="code-string">$1</span>')
            .replace(/\b(true|false|null)\b/g, '<span class="code-boolean">$1</span>');
    }
    if (language === 'json') {
        return escaped
            .replace(/(&quot;(?:[^&]|&(?!quot;))*&quot;)(\s*:)/g, '<span class="code-key">$1</span>$2')
            .replace(/:(\s*)(&quot;(?:[^&]|&(?!quot;))*&quot;)/g, ':$1<span class="code-string">$2</span>')
            .replace(/\b(true|false|null)\b/g, '<span class="code-boolean">$1</span>')
            .replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="code-number">$1</span>');
    }
    return escaped;
}

export function CodeBlock({
    code,
    language = 'bash',
    title,
    showLineNumbers = true,
    highlightLines = [],
    className = '',
}: CodeBlockProps) {
    const [copied, setCopied] = useState(false);
    const codeRef = useRef<HTMLPreElement>(null);

    const handleCopy = useCallback(async () => {
        try {
            await navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    }, [code]);

    const handleKeyDown = useCallback(
        (e: React.KeyboardEvent) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleCopy();
            }
        },
        [handleCopy]
    );

    const lines = code.split('\n');
    const Icon = languageIcons[language] || FileCode;

    return (
        <div
            className={`rounded-lg border border-slate-700 bg-slate-900 overflow-hidden ${className}`}
        >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
                <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-slate-400" />
                    <span className="text-sm text-slate-400">
                        {title || languageLabels[language] || language.toUpperCase()}
                    </span>
                </div>
                <button
                    onClick={handleCopy}
                    onKeyDown={handleKeyDown}
                    className="flex items-center gap-1.5 px-2 py-1 text-xs text-slate-400 hover:text-white hover:bg-slate-700 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                    aria-label={copied ? '복사됨' : '코드 복사'}
                    tabIndex={0}
                >
                    {copied ? (
                        <>
                            <Check className="h-3.5 w-3.5 text-green-400" />
                            <span className="text-green-400">복사됨</span>
                        </>
                    ) : (
                        <>
                            <Copy className="h-3.5 w-3.5" />
                            <span>복사</span>
                        </>
                    )}
                </button>
            </div>

            {/* Code Content */}
            <div className="overflow-x-auto custom-scrollbar">
                <pre
                    ref={codeRef}
                    className="p-4 text-sm font-mono leading-relaxed"
                >
                    <code>
                        {lines.map((line, index) => {
                            const lineNumber = index + 1;
                            const isHighlighted = highlightLines.includes(lineNumber);
                            const highlightedLine = highlightCode(line, language);

                            return (
                                <div
                                    key={index}
                                    className={`flex ${isHighlighted
                                        ? 'bg-blue-500/20 -mx-4 px-4'
                                        : ''
                                        }`}
                                >
                                    {showLineNumbers && (
                                        <span className="select-none w-8 pr-4 text-right text-slate-600 flex-shrink-0">
                                            {lineNumber}
                                        </span>
                                    )}
                                    <span
                                        className="text-slate-300 flex-1"
                                        dangerouslySetInnerHTML={{
                                            __html: highlightedLine || '&nbsp;',
                                        }}
                                    />
                                </div>
                            );
                        })}
                    </code>
                </pre>
            </div>
        </div>
    );
}

export default CodeBlock;
