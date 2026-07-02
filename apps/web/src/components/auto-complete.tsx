'use client';

import * as React from 'react';
import { Search, X, Loader2, AlertTriangle, FolderKanban, Package, Hash } from 'lucide-react';

// ============================================
// Types
// ============================================
export interface AutoCompleteOption {
    id: string;
    label: string;
    type: 'cve' | 'project' | 'package' | 'image';
    sublabel?: string;
    metadata?: Record<string, any>;
}

// ============================================
// AutoComplete Component
// ============================================
export interface AutoCompleteProps {
    value: string;
    onChange: (value: string) => void;
    onSelect: (option: AutoCompleteOption) => void;
    options: AutoCompleteOption[];
    loading?: boolean;
    placeholder?: string;
    debounceMs?: number;
    className?: string;
}

export function AutoComplete({
    value,
    onChange,
    onSelect,
    options,
    loading = false,
    placeholder = '검색...',
    debounceMs = 300,
    className,
}: AutoCompleteProps) {
    const [isOpen, setIsOpen] = React.useState(false);
    const [inputValue, setInputValue] = React.useState(value);
    const [highlightedIndex, setHighlightedIndex] = React.useState(-1);
    const inputRef = React.useRef<HTMLInputElement>(null);
    const listRef = React.useRef<HTMLDivElement>(null);
    const debounceRef = React.useRef<NodeJS.Timeout>();

    // Sync external value
    React.useEffect(() => {
        setInputValue(value);
    }, [value]);

    // Debounced onChange
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newValue = e.target.value;
        setInputValue(newValue);
        setIsOpen(true);
        setHighlightedIndex(-1);

        if (debounceRef.current) {
            clearTimeout(debounceRef.current);
        }

        debounceRef.current = setTimeout(() => {
            onChange(newValue);
        }, debounceMs);
    };

    // Keyboard navigation
    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (!isOpen || options.length === 0) {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                setIsOpen(true);
            }
            return;
        }

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                setHighlightedIndex((prev) =>
                    prev < options.length - 1 ? prev + 1 : 0
                );
                break;
            case 'ArrowUp':
                e.preventDefault();
                setHighlightedIndex((prev) =>
                    prev > 0 ? prev - 1 : options.length - 1
                );
                break;
            case 'Enter':
                e.preventDefault();
                if (highlightedIndex >= 0 && options[highlightedIndex]) {
                    handleSelect(options[highlightedIndex]);
                }
                break;
            case 'Escape':
                setIsOpen(false);
                setHighlightedIndex(-1);
                break;
        }
    };

    const handleSelect = (option: AutoCompleteOption) => {
        setInputValue(option.label);
        setIsOpen(false);
        setHighlightedIndex(-1);
        onSelect(option);
    };

    const handleClear = () => {
        setInputValue('');
        onChange('');
        inputRef.current?.focus();
    };

    // Scroll highlighted item into view
    React.useEffect(() => {
        if (highlightedIndex >= 0 && listRef.current) {
            const item = listRef.current.children[highlightedIndex] as HTMLElement;
            item?.scrollIntoView({ block: 'nearest' });
        }
    }, [highlightedIndex]);

    // Close on outside click
    React.useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (inputRef.current && !inputRef.current.parentElement?.contains(e.target as Node)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    return (
        <div className={`relative ${className || ''}`}>
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                    ref={inputRef}
                    type="text"
                    value={inputValue}
                    onChange={handleInputChange}
                    onKeyDown={handleKeyDown}
                    onFocus={() => inputValue && setIsOpen(true)}
                    placeholder={placeholder}
                    className="w-full pl-10 pr-10 py-2 text-sm bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    role="combobox"
                    aria-expanded={isOpen}
                    aria-autocomplete="list"
                    aria-controls="autocomplete-list"
                />
                {loading ? (
                    <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 animate-spin" />
                ) : inputValue ? (
                    <button
                        onClick={handleClear}
                        className="absolute right-3 top-1/2 -translate-y-1/2 p-0.5 rounded hover:bg-slate-100 dark:hover:bg-slate-700"
                    >
                        <X className="h-4 w-4 text-slate-400" />
                    </button>
                ) : null}
            </div>

            {isOpen && (inputValue || options.length > 0) && (
                <div
                    ref={listRef}
                    id="autocomplete-list"
                    className="absolute z-50 w-full mt-1 bg-white dark:bg-slate-800 rounded-lg shadow-lg border border-slate-200 dark:border-slate-700 max-h-[300px] overflow-auto"
                    role="listbox"
                >
                    {loading ? (
                        <div className="flex items-center justify-center py-8">
                            <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
                        </div>
                    ) : options.length === 0 ? (
                        <div className="py-8 text-center text-sm text-slate-500 dark:text-slate-400">
                            검색 결과가 없습니다
                        </div>
                    ) : (
                        options.map((option, index) => (
                            <AutoCompleteItem
                                key={option.id}
                                option={option}
                                isHighlighted={index === highlightedIndex}
                                onClick={() => handleSelect(option)}
                            />
                        ))
                    )}
                </div>
            )}
        </div>
    );
}

// ============================================
// AutoComplete Item
// ============================================
interface AutoCompleteItemProps {
    option: AutoCompleteOption;
    isHighlighted: boolean;
    onClick: () => void;
}

function AutoCompleteItem({ option, isHighlighted, onClick }: AutoCompleteItemProps) {
    const typeConfig = {
        cve: { icon: AlertTriangle, color: 'text-red-500', label: 'CVE' },
        project: { icon: FolderKanban, color: 'text-blue-500', label: '프로젝트' },
        package: { icon: Package, color: 'text-purple-500', label: '패키지' },
        image: { icon: Hash, color: 'text-green-500', label: '이미지' },
    };

    const config = typeConfig[option.type];
    const Icon = config.icon;

    return (
        <button
            onClick={onClick}
            className={`w-full flex items-center gap-3 px-3 py-2 text-left transition-colors ${isHighlighted
                    ? 'bg-blue-50 dark:bg-blue-900/20'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-700/50'
                }`}
            role="option"
            aria-selected={isHighlighted}
        >
            <div className={`flex-shrink-0 ${config.color}`}>
                <Icon className="h-4 w-4" />
            </div>
            <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                    {option.label}
                </p>
                {option.sublabel && (
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                        {option.sublabel}
                    </p>
                )}
            </div>
            <span className="flex-shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">
                {config.label}
            </span>
        </button>
    );
}

// ============================================
// Search with Type Filters
// ============================================
export interface TypedSearchProps {
    onSearch: (query: string, types: string[]) => void;
    placeholder?: string;
    className?: string;
}

export function TypedSearch({ onSearch, placeholder = 'CVE, 프로젝트, 패키지 검색...', className }: TypedSearchProps) {
    const [query, setQuery] = React.useState('');
    const [selectedTypes, setSelectedTypes] = React.useState<string[]>([]);

    const types = [
        { key: 'cve', label: 'CVE' },
        { key: 'project', label: '프로젝트' },
        { key: 'package', label: '패키지' },
    ];

    const handleSearch = () => {
        onSearch(query, selectedTypes);
    };

    const toggleType = (type: string) => {
        setSelectedTypes((prev) =>
            prev.includes(type)
                ? prev.filter((t) => t !== type)
                : [...prev, type]
        );
    };

    return (
        <div className={className}>
            <div className="flex gap-2">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                    <input
                        type="text"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                        placeholder={placeholder}
                        className="w-full pl-10 pr-4 py-2 text-sm bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>
                <button
                    onClick={handleSearch}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                >
                    검색
                </button>
            </div>
            <div className="flex gap-2 mt-2">
                {types.map((type) => (
                    <button
                        key={type.key}
                        onClick={() => toggleType(type.key)}
                        className={`px-3 py-1 text-xs rounded-full transition-colors ${selectedTypes.includes(type.key)
                                ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                                : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
                            }`}
                    >
                        {type.label}
                    </button>
                ))}
            </div>
        </div>
    );
}
