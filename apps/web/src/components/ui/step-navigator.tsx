'use client';

import { useCallback } from 'react';
import { Check } from 'lucide-react';

export interface Step {
    id: string;
    title: string;
    description?: string;
}

export interface StepNavigatorProps {
    steps: Step[];
    currentStep: number;
    completedSteps?: number[];
    onStepClick?: (stepIndex: number) => void;
    className?: string;
}

export function StepNavigator({
    steps,
    currentStep,
    completedSteps = [],
    onStepClick,
    className = '',
}: StepNavigatorProps) {
    const handleStepClick = useCallback(
        (index: number) => {
            if (onStepClick) {
                onStepClick(index);
            }
        },
        [onStepClick]
    );

    const handleKeyDown = useCallback(
        (e: React.KeyboardEvent, index: number) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleStepClick(index);
            }
        },
        [handleStepClick]
    );

    return (
        <nav className={`${className}`} aria-label="진행 단계">
            <ol className="flex items-center">
                {steps.map((step, index) => {
                    const isCompleted = completedSteps.includes(index);
                    const isCurrent = index === currentStep;
                    const isPast = index < currentStep;
                    const isClickable = !!onStepClick;

                    return (
                        <li
                            key={step.id}
                            className={`flex items-center ${index !== steps.length - 1 ? 'flex-1' : ''
                                }`}
                        >
                            {/* Step Circle */}
                            <div
                                role={isClickable ? 'button' : undefined}
                                tabIndex={isClickable ? 0 : undefined}
                                onClick={() => handleStepClick(index)}
                                onKeyDown={(e) => handleKeyDown(e, index)}
                                className={`flex items-center justify-center w-10 h-10 rounded-full border-2 transition-all ${isClickable
                                        ? 'cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'
                                        : ''
                                    } ${isCompleted || isPast
                                        ? 'bg-blue-600 border-blue-600 text-white'
                                        : isCurrent
                                            ? 'bg-blue-100 border-blue-600 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'
                                            : 'bg-slate-100 border-slate-300 text-slate-500 dark:bg-slate-800 dark:border-slate-600 dark:text-slate-400'
                                    }`}
                                aria-current={isCurrent ? 'step' : undefined}
                            >
                                {isCompleted || isPast ? (
                                    <Check className="w-5 h-5" />
                                ) : (
                                    <span className="text-sm font-semibold">
                                        {index + 1}
                                    </span>
                                )}
                            </div>

                            {/* Step Label */}
                            <div className="ml-3 min-w-0">
                                <p
                                    className={`text-sm font-medium ${isCurrent
                                            ? 'text-blue-600 dark:text-blue-400'
                                            : isCompleted || isPast
                                                ? 'text-slate-900 dark:text-white'
                                                : 'text-slate-500 dark:text-slate-400'
                                        }`}
                                >
                                    {step.title}
                                </p>
                                {step.description && (
                                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate max-w-[120px]">
                                        {step.description}
                                    </p>
                                )}
                            </div>

                            {/* Connector Line */}
                            {index !== steps.length - 1 && (
                                <div
                                    className={`flex-1 h-0.5 mx-4 ${isPast
                                            ? 'bg-blue-600'
                                            : 'bg-slate-200 dark:bg-slate-700'
                                        }`}
                                />
                            )}
                        </li>
                    );
                })}
            </ol>
        </nav>
    );
}

// Vertical version for mobile or sidebar
export function StepNavigatorVertical({
    steps,
    currentStep,
    completedSteps = [],
    onStepClick,
    className = '',
}: StepNavigatorProps) {
    const handleStepClick = useCallback(
        (index: number) => {
            if (onStepClick) {
                onStepClick(index);
            }
        },
        [onStepClick]
    );

    return (
        <nav className={`${className}`} aria-label="진행 단계">
            <ol className="space-y-4">
                {steps.map((step, index) => {
                    const isCompleted = completedSteps.includes(index);
                    const isCurrent = index === currentStep;
                    const isPast = index < currentStep;
                    const isClickable = !!onStepClick;

                    return (
                        <li key={step.id} className="flex items-start gap-3">
                            {/* Left side with circle and line */}
                            <div className="flex flex-col items-center">
                                <div
                                    role={isClickable ? 'button' : undefined}
                                    tabIndex={isClickable ? 0 : undefined}
                                    onClick={() => handleStepClick(index)}
                                    className={`flex items-center justify-center w-8 h-8 rounded-full border-2 transition-all ${isClickable ? 'cursor-pointer' : ''
                                        } ${isCompleted || isPast
                                            ? 'bg-blue-600 border-blue-600 text-white'
                                            : isCurrent
                                                ? 'bg-blue-100 border-blue-600 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'
                                                : 'bg-slate-100 border-slate-300 text-slate-500 dark:bg-slate-800 dark:border-slate-600'
                                        }`}
                                    aria-current={isCurrent ? 'step' : undefined}
                                >
                                    {isCompleted || isPast ? (
                                        <Check className="w-4 h-4" />
                                    ) : (
                                        <span className="text-xs font-semibold">
                                            {index + 1}
                                        </span>
                                    )}
                                </div>
                                {index !== steps.length - 1 && (
                                    <div
                                        className={`w-0.5 h-8 mt-2 ${isPast
                                                ? 'bg-blue-600'
                                                : 'bg-slate-200 dark:bg-slate-700'
                                            }`}
                                    />
                                )}
                            </div>

                            {/* Content */}
                            <div className="pt-1">
                                <p
                                    className={`text-sm font-medium ${isCurrent
                                            ? 'text-blue-600 dark:text-blue-400'
                                            : isCompleted || isPast
                                                ? 'text-slate-900 dark:text-white'
                                                : 'text-slate-500 dark:text-slate-400'
                                        }`}
                                >
                                    {step.title}
                                </p>
                                {step.description && (
                                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                                        {step.description}
                                    </p>
                                )}
                            </div>
                        </li>
                    );
                })}
            </ol>
        </nav>
    );
}

export default StepNavigator;
