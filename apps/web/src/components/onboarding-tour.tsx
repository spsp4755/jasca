'use client';

import * as React from 'react';
import { createPortal } from 'react-dom';
import { X, ChevronLeft, ChevronRight, Check } from 'lucide-react';

// ============================================
// Types
// ============================================
export interface OnboardingStep {
    id: string;
    title: string;
    description: string;
    target?: string; // CSS selector for element highlight
    position?: 'top' | 'bottom' | 'left' | 'right' | 'center';
    action?: {
        label: string;
        onClick: () => void;
    };
}

// ============================================
// Onboarding Tour Context
// ============================================
interface OnboardingContextType {
    isActive: boolean;
    currentStep: number;
    startTour: (tourId: string) => void;
    endTour: () => void;
    nextStep: () => void;
    prevStep: () => void;
    skipTour: () => void;
}

const OnboardingContext = React.createContext<OnboardingContextType | null>(null);

export function useOnboarding() {
    const context = React.useContext(OnboardingContext);
    if (!context) {
        throw new Error('useOnboarding must be used within OnboardingProvider');
    }
    return context;
}

// ============================================
// Onboarding Provider
// ============================================
const COMPLETED_TOURS_KEY = 'jasca_completed_tours';

interface OnboardingProviderProps {
    children: React.ReactNode;
    tours: Record<string, OnboardingStep[]>;
}

export function OnboardingProvider({ children, tours }: OnboardingProviderProps) {
    const [activeTourId, setActiveTourId] = React.useState<string | null>(null);
    const [currentStep, setCurrentStep] = React.useState(0);
    const [mounted, setMounted] = React.useState(false);

    React.useEffect(() => {
        setMounted(true);
    }, []);

    const currentTour = activeTourId ? tours[activeTourId] : null;

    const startTour = React.useCallback((tourId: string) => {
        // Check if tour was already completed
        try {
            const completed = JSON.parse(localStorage.getItem(COMPLETED_TOURS_KEY) || '[]');
            if (completed.includes(tourId)) return;
        } catch { }

        setActiveTourId(tourId);
        setCurrentStep(0);
    }, []);

    const endTour = React.useCallback(() => {
        if (activeTourId) {
            try {
                const completed = JSON.parse(localStorage.getItem(COMPLETED_TOURS_KEY) || '[]');
                if (!completed.includes(activeTourId)) {
                    localStorage.setItem(COMPLETED_TOURS_KEY, JSON.stringify([...completed, activeTourId]));
                }
            } catch { }
        }
        setActiveTourId(null);
        setCurrentStep(0);
    }, [activeTourId]);

    const nextStep = React.useCallback(() => {
        if (currentTour && currentStep < currentTour.length - 1) {
            setCurrentStep((prev) => prev + 1);
        } else {
            endTour();
        }
    }, [currentTour, currentStep, endTour]);

    const prevStep = React.useCallback(() => {
        if (currentStep > 0) {
            setCurrentStep((prev) => prev - 1);
        }
    }, [currentStep]);

    const skipTour = React.useCallback(() => {
        endTour();
    }, [endTour]);

    const value = React.useMemo(() => ({
        isActive: !!activeTourId,
        currentStep,
        startTour,
        endTour,
        nextStep,
        prevStep,
        skipTour,
    }), [activeTourId, currentStep, startTour, endTour, nextStep, prevStep, skipTour]);

    return (
        <OnboardingContext.Provider value={value}>
            {children}
            {mounted && currentTour && activeTourId && (
                <OnboardingOverlay
                    steps={currentTour}
                    currentStep={currentStep}
                    onNext={nextStep}
                    onPrev={prevStep}
                    onSkip={skipTour}
                    onComplete={endTour}
                />
            )}
        </OnboardingContext.Provider>
    );
}

// ============================================
// Onboarding Overlay
// ============================================
interface OnboardingOverlayProps {
    steps: OnboardingStep[];
    currentStep: number;
    onNext: () => void;
    onPrev: () => void;
    onSkip: () => void;
    onComplete: () => void;
}

function OnboardingOverlay({ steps, currentStep, onNext, onPrev, onSkip, onComplete }: OnboardingOverlayProps) {
    const step = steps[currentStep];
    const isLastStep = currentStep === steps.length - 1;
    const isFirstStep = currentStep === 0;

    const [targetRect, setTargetRect] = React.useState<DOMRect | null>(null);

    // Find target element position
    React.useEffect(() => {
        if (step.target) {
            const element = document.querySelector(step.target);
            if (element) {
                setTargetRect(element.getBoundingClientRect());
                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } else {
                setTargetRect(null);
            }
        } else {
            setTargetRect(null);
        }
    }, [step.target]);

    // Calculate tooltip position
    const getTooltipStyle = (): React.CSSProperties => {
        if (!targetRect || step.position === 'center') {
            return {
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
            };
        }

        const padding = 16;
        const tooltipWidth = 320;

        switch (step.position || 'bottom') {
            case 'top':
                return {
                    bottom: `${window.innerHeight - targetRect.top + padding}px`,
                    left: `${targetRect.left + targetRect.width / 2}px`,
                    transform: 'translateX(-50%)',
                };
            case 'bottom':
                return {
                    top: `${targetRect.bottom + padding}px`,
                    left: `${targetRect.left + targetRect.width / 2}px`,
                    transform: 'translateX(-50%)',
                };
            case 'left':
                return {
                    top: `${targetRect.top + targetRect.height / 2}px`,
                    right: `${window.innerWidth - targetRect.left + padding}px`,
                    transform: 'translateY(-50%)',
                };
            case 'right':
                return {
                    top: `${targetRect.top + targetRect.height / 2}px`,
                    left: `${targetRect.right + padding}px`,
                    transform: 'translateY(-50%)',
                };
            default:
                return {};
        }
    };

    return createPortal(
        <>
            {/* Backdrop with spotlight */}
            <div className="fixed inset-0 z-[100]">
                {targetRect ? (
                    <svg className="w-full h-full absolute" style={{ pointerEvents: 'none' }}>
                        <defs>
                            <mask id="spotlight-mask">
                                <rect x="0" y="0" width="100%" height="100%" fill="white" />
                                <rect
                                    x={targetRect.left - 8}
                                    y={targetRect.top - 8}
                                    width={targetRect.width + 16}
                                    height={targetRect.height + 16}
                                    fill="black"
                                    rx="8"
                                />
                            </mask>
                        </defs>
                        <rect
                            x="0"
                            y="0"
                            width="100%"
                            height="100%"
                            fill="rgba(0, 0, 0, 0.7)"
                            mask="url(#spotlight-mask)"
                        />
                    </svg>
                ) : (
                    <div className="w-full h-full bg-black/70" />
                )}
            </div>

            {/* Tooltip */}
            <div
                className="fixed z-[101] bg-white dark:bg-slate-800 rounded-xl shadow-xl p-6 max-w-[320px] animate-in fade-in zoom-in-95 duration-200"
                style={getTooltipStyle()}
            >
                {/* Close button */}
                <button
                    onClick={onSkip}
                    className="absolute top-3 right-3 p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-700"
                    aria-label="닫기"
                >
                    <X className="h-4 w-4 text-slate-400" />
                </button>

                {/* Step indicator */}
                <div className="flex items-center gap-1 mb-3">
                    {steps.map((_, index) => (
                        <div
                            key={index}
                            className={`w-2 h-2 rounded-full transition-colors ${index === currentStep
                                    ? 'bg-blue-600'
                                    : index < currentStep
                                        ? 'bg-blue-300'
                                        : 'bg-slate-200 dark:bg-slate-600'
                                }`}
                        />
                    ))}
                </div>

                {/* Content */}
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                    {step.title}
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                    {step.description}
                </p>

                {/* Custom action */}
                {step.action && (
                    <button
                        onClick={step.action.onClick}
                        className="w-full mb-4 px-4 py-2 text-sm font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 dark:bg-blue-900/30 dark:hover:bg-blue-900/50 rounded-lg transition-colors"
                    >
                        {step.action.label}
                    </button>
                )}

                {/* Navigation */}
                <div className="flex items-center justify-between">
                    <button
                        onClick={onPrev}
                        disabled={isFirstStep}
                        className={`flex items-center gap-1 text-sm ${isFirstStep
                                ? 'text-slate-300 dark:text-slate-600 cursor-not-allowed'
                                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                            }`}
                    >
                        <ChevronLeft className="h-4 w-4" />
                        이전
                    </button>

                    <button
                        onClick={isLastStep ? onComplete : onNext}
                        className="flex items-center gap-1 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                    >
                        {isLastStep ? (
                            <>
                                <Check className="h-4 w-4" />
                                완료
                            </>
                        ) : (
                            <>
                                다음
                                <ChevronRight className="h-4 w-4" />
                            </>
                        )}
                    </button>
                </div>
            </div>
        </>,
        document.body
    );
}

// ============================================
// Default Tours
// ============================================
export const defaultTours: Record<string, OnboardingStep[]> = {
    dashboard: [
        {
            id: 'welcome',
            title: 'JASCA에 오신 것을 환영합니다!',
            description: '취약점 관리 시스템 JASCA의 주요 기능을 소개해 드릴게요.',
            position: 'center',
        },
        {
            id: 'stats',
            title: '취약점 현황',
            description: '상단 카드에서 Critical, High 등 심각도별 취약점 현황을 한눈에 확인할 수 있습니다. 카드를 클릭하면 해당 취약점 목록으로 이동합니다.',
            target: '[data-tour="stat-cards"]',
            position: 'bottom',
        },
        {
            id: 'navigation',
            title: '네비게이션',
            description: '왼쪽 사이드바에서 프로젝트, 스캔, 취약점, 정책 등 다양한 메뉴에 접근할 수 있습니다.',
            target: '[data-tour="sidebar"]',
            position: 'right',
        },
        {
            id: 'shortcuts',
            title: '키보드 단축키',
            description: '? 키를 눌러 키보드 단축키를 확인하고, Ctrl+K로 빠른 검색을 사용할 수 있습니다.',
            position: 'center',
        },
    ],
};
