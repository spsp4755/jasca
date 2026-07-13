'use client';

import { useState, useEffect } from 'react';
import {
    Cpu,
    Save,
    RotateCcw,
    CheckCircle,
    AlertTriangle,
    Settings,
    Database,
    FileJson,
    Clock,
    Loader2,
    RefreshCw,
    HelpCircle,
    Info,
    XCircle,
    AlertCircle,
    Terminal,
    Shield,
    Globe,
} from 'lucide-react';
import { useCheckovSettings, useTrivySettings, useUpdateSettings, useZapConnectionTest, useZapSettings, type CheckovSettings, type TrivySettings, type ZapSettings, type ZapTargetProfile } from '@/lib/api-hooks';

interface ValidationResult {
    name: string;
    passed: boolean;
    message: string;
}

interface TestConfigResult {
    success: boolean;
    settings: TrivySettings;
    trivyVersion: string | null;
    dbExists: boolean;
    dbHealthy: boolean;
    validations: ValidationResult[];
}

const defaultConfig: TrivySettings = {
    outputFormat: 'json',
    schemaVersion: 2,
    severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    ignoreUnfixed: false,
    timeout: '10m',
    cacheDir: '/tmp/trivy-cache',
    scanners: ['vuln', 'license'],
};

const defaultCheckovConfig: CheckovSettings = {
    allowInternalModuleDownload: false,
};

const defaultZapConfig: ZapSettings = {
    enabled: false,
    zapBaseUrl: 'http://zap-scanner:8080',
    apiKeyConfigured: false,
    apiKey: '',
    connectTimeoutSeconds: 10,
    maxScanDurationMinutes: 30,
    maxConcurrentScans: 1,
    allowBaselineScan: true,
    allowActiveScan: false,
    allowedTargetPatterns: [],
    blockedTargetPatterns: [],
    defaultRiskThresholdForNotification: 'HIGH',
    targetProfiles: [],
};

const normalizeScanners = (scanners?: string[]) => {
    const allowed = new Set(['vuln', 'license', 'misconfig', 'secret']);
    const normalized = (scanners || [])
        .map((scanner) => scanner === 'config' ? 'misconfig' : scanner)
        .filter((scanner) => allowed.has(scanner));
    return normalized.length ? Array.from(new Set(normalized)) : defaultConfig.scanners;
};

export default function TrivySettingsPage() {
    const { data: settings, isLoading, error, refetch } = useTrivySettings();
    const { data: checkovSettings, isLoading: isCheckovLoading, error: checkovError, refetch: refetchCheckov } = useCheckovSettings();
    const { data: zapSettings, isLoading: isZapLoading, error: zapError, refetch: refetchZap } = useZapSettings();
    const updateMutation = useUpdateSettings();
    const zapConnectionMutation = useZapConnectionTest();

    const [config, setConfig] = useState<TrivySettings>(defaultConfig);
    const [checkovConfig, setCheckovConfig] = useState<CheckovSettings>(defaultCheckovConfig);
    const [zapConfig, setZapConfig] = useState<ZapSettings>(defaultZapConfig);
    const [saved, setSaved] = useState(false);
    const [hasChanges, setHasChanges] = useState(false);
    const [testResult, setTestResult] = useState<'success' | 'error' | 'testing' | null>(null);
    const [activeTab, setActiveTab] = useState<'settings' | 'help'>('settings');
    const [testDetails, setTestDetails] = useState<TestConfigResult | null>(null);

    // Load settings from API
    useEffect(() => {
        if (settings) {
            setConfig({ ...defaultConfig, ...settings, scanners: normalizeScanners(settings.scanners) });
        }
    }, [settings]);

    useEffect(() => {
        if (checkovSettings) {
            setCheckovConfig({ ...defaultCheckovConfig, ...checkovSettings });
        }
    }, [checkovSettings]);

    useEffect(() => {
        if (zapSettings) {
            setZapConfig({
                ...defaultZapConfig,
                ...zapSettings,
                apiKey: '',
                allowedTargetPatterns: zapSettings.allowedTargetPatterns || [],
                blockedTargetPatterns: zapSettings.blockedTargetPatterns || [],
                targetProfiles: zapSettings.targetProfiles || [],
            });
        }
    }, [zapSettings]);

    const handleSave = async () => {
        try {
            await Promise.all([
                updateMutation.mutateAsync({
                    key: 'trivy',
                    value: config,
                }),
                updateMutation.mutateAsync({
                    key: 'checkov',
                    value: checkovConfig,
                }),
                updateMutation.mutateAsync({
                    key: 'zap',
                    value: zapConfig,
                }),
            ]);
            setSaved(true);
            setHasChanges(false);
            setTimeout(() => setSaved(false), 3000);
        } catch (err) {
            console.error('Failed to save trivy settings:', err);
        }
    };

    const handleReset = () => {
        setConfig(defaultConfig);
        setCheckovConfig(defaultCheckovConfig);
        setZapConfig(defaultZapConfig);
        setHasChanges(true);
    };

    const updateCheckovConfig = <K extends keyof CheckovSettings>(key: K, value: CheckovSettings[K]) => {
        setCheckovConfig(prev => ({ ...prev, [key]: value }));
        setHasChanges(true);
    };

    const updateZapConfig = <K extends keyof ZapSettings>(key: K, value: ZapSettings[K]) => {
        setZapConfig(prev => ({ ...prev, [key]: value }));
        setHasChanges(true);
    };

    const updateZapPatternList = (key: 'allowedTargetPatterns' | 'blockedTargetPatterns', value: string) => {
        updateZapConfig(key, value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean));
    };

    const addZapProfile = () => {
        const id = crypto.randomUUID ? crypto.randomUUID() : `zap-profile-${Date.now()}`;
        updateZapConfig('targetProfiles', [...zapConfig.targetProfiles, {
            id,
            name: '새 대상 프로필',
            enabled: true,
            allowedTargetPatterns: [],
            blockedTargetPatterns: [],
            maxScanDurationMinutes: Math.min(10, zapConfig.maxScanDurationMinutes),
            defaultRiskThresholdForNotification: zapConfig.defaultRiskThresholdForNotification,
        }]);
    };

    const updateZapProfile = (id: string, changes: Partial<ZapTargetProfile>) => {
        updateZapConfig('targetProfiles', zapConfig.targetProfiles.map((profile) => profile.id === id ? { ...profile, ...changes } : profile));
    };

    const updateZapProfilePatterns = (id: string, key: 'allowedTargetPatterns' | 'blockedTargetPatterns', value: string) => {
        updateZapProfile(id, { [key]: value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) });
    };

    const testZapConnection = () => zapConnectionMutation.mutate();

    const handleTest = async () => {
        setTestResult('testing');
        setTestDetails(null);
        try {
            const token = localStorage.getItem('accessToken');
            const response = await fetch('/api/trivy-db/test-config', {
                headers: { 'Authorization': `Bearer ${token}` },
            });
            const data = await response.json();
            setTestDetails(data);
            setTestResult(data.success ? 'success' : 'error');
        } catch (err) {
            setTestResult('error');
        }
        setTimeout(() => {
            setTestResult(null);
        }, 10000);
    };

    const toggleSeverity = (severity: string) => {
        setConfig(prev => ({
            ...prev,
            severities: prev.severities.includes(severity)
                ? prev.severities.filter(s => s !== severity)
                : [...prev.severities, severity]
        }));
        setHasChanges(true);
    };

    const toggleScanner = (scanner: string) => {
        setConfig(prev => ({
            ...prev,
            scanners: prev.scanners.includes(scanner)
                ? prev.scanners.filter(s => s !== scanner)
                : [...prev.scanners, scanner]
        }));
        setHasChanges(true);
    };

    const updateConfig = <K extends keyof TrivySettings>(key: K, value: TrivySettings[K]) => {
        setConfig(prev => ({ ...prev, [key]: value }));
        setHasChanges(true);
    };

    if (isLoading || isCheckovLoading || isZapLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            </div>
        );
    }

    if (error || checkovError || zapError) {
        return (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6 text-center">
                <AlertTriangle className="h-12 w-12 mx-auto text-red-500 mb-4" />
                <h3 className="text-lg font-semibold text-red-800 dark:text-red-200 mb-2">오류 발생</h3>
                <p className="text-red-600 dark:text-red-300 mb-4">Trivy 설정을 불러오는데 실패했습니다.</p>
                <button
                    onClick={() => refetch()}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                >
                    다시 시도
                </button>
            </div>
        );
    }

    return (
        <div className="space-y-6 max-w-3xl">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Trivy 설정</h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1">
                        Trivy 스캐너 동작 설정을 관리합니다
                    </p>
                </div>
                <button
                    onClick={() => {
                        refetch();
                        refetchCheckov();
                        refetchZap();
                    }}
                    disabled={isLoading || isCheckovLoading || isZapLoading}
                    className="p-2 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
                >
                    <RefreshCw className={`h-5 w-5 ${isLoading || isCheckovLoading || isZapLoading ? 'animate-spin' : ''}`} />
                </button>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg w-fit">
                <button
                    onClick={() => setActiveTab('settings')}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                        activeTab === 'settings'
                            ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                >
                    <Settings className="h-4 w-4" />
                    설정
                </button>
                <button
                    onClick={() => setActiveTab('help')}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                        activeTab === 'help'
                            ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                >
                    <HelpCircle className="h-4 w-4" />
                    사용법 안내
                </button>
            </div>

            {/* Help Content */}
            {activeTab === 'help' && (
                <div className="space-y-6">
                    {/* Overview */}
                    <div className="bg-gradient-to-r from-cyan-50 to-blue-50 dark:from-cyan-900/20 dark:to-blue-900/20 rounded-xl p-6 border border-cyan-200 dark:border-cyan-800">
                        <div className="flex items-start gap-4">
                            <div className="p-3 bg-cyan-100 dark:bg-cyan-800 rounded-lg">
                                <Shield className="h-6 w-6 text-cyan-600 dark:text-cyan-400" />
                            </div>
                            <div>
                                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                                    Trivy 설정이란?
                                </h3>
                                <p className="text-slate-600 dark:text-slate-400">
                                    Trivy는 컨테이너 이미지, 파일 시스템, Git 저장소의 취약점을 스캔하는 도구입니다.
                                    여기서 설정한 옵션들은 Trivy 스캔 실행 시 자동으로 적용됩니다.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Settings Explanation */}
                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <Settings className="h-5 w-5 text-blue-600" />
                            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                                설정 항목 설명
                            </h3>
                        </div>

                        <div className="space-y-4">
                            <div className="p-4 bg-slate-50 dark:bg-slate-900 rounded-lg">
                                <h4 className="font-medium text-slate-900 dark:text-white mb-2">심각도 필터</h4>
                                <p className="text-sm text-slate-600 dark:text-slate-400">
                                    스캔 결과에서 표시할 취약점의 심각도를 선택합니다. CRITICAL, HIGH를 선택하면 중요한 취약점만 표시됩니다.
                                </p>
                            </div>
                            <div className="p-4 bg-slate-50 dark:bg-slate-900 rounded-lg">
                                <h4 className="font-medium text-slate-900 dark:text-white mb-2">스캐너 유형</h4>
                                <p className="text-sm text-slate-600 dark:text-slate-400">
                                    <strong>취약점</strong>: 알려진 CVE 취약점 검사 | <strong>시크릿</strong>: 하드코딩된 비밀키 검사 |
                                    <strong>설정 오류</strong>: 잘못된 설정 검사
                                </p>
                            </div>
                            <div className="p-4 bg-slate-50 dark:bg-slate-900 rounded-lg">
                                <h4 className="font-medium text-slate-900 dark:text-white mb-2">수정사항 없는 취약점 무시</h4>
                                <p className="text-sm text-slate-600 dark:text-slate-400">
                                    활성화하면 아직 패치가 없는 취약점을 결과에서 제외합니다. 조치 가능한 취약점에만 집중할 수 있습니다.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Integration Info */}
                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <Database className="h-5 w-5 text-purple-600" />
                            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                                연동 방식
                            </h3>
                        </div>

                        <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4 mb-4">
                            <div className="flex items-start gap-2">
                                <Info className="h-5 w-5 text-purple-600 dark:text-purple-400 mt-0.5 flex-shrink-0" />
                                <p className="text-sm text-purple-700 dark:text-purple-300">
                                    이 설정은 <strong>Trivy DB</strong> 메뉴의 스캔 기능에 자동으로 적용됩니다.
                                </p>
                            </div>
                        </div>

                        <div className="space-y-3 text-sm text-slate-600 dark:text-slate-400">
                            <div className="flex items-center gap-2">
                                <CheckCircle className="h-4 w-4 text-green-500" />
                                취약점 조회 시 설정된 심각도 필터 자동 적용
                            </div>
                            <div className="flex items-center gap-2">
                                <CheckCircle className="h-4 w-4 text-green-500" />
                                설정된 타임아웃 시간 적용
                            </div>
                            <div className="flex items-center gap-2">
                                <CheckCircle className="h-4 w-4 text-green-500" />
                                수정사항 없는 취약점 무시 옵션 적용
                            </div>
                        </div>
                    </div>

                    {/* Test Results */}
                    {testDetails && (
                        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                                <Terminal className="h-5 w-5" />
                                설정 검증 결과
                            </h3>
                            <div className="space-y-2">
                                {testDetails.validations.map((v, i) => (
                                    <div key={i} className={`flex items-center justify-between p-3 rounded-lg ${
                                        v.passed ? 'bg-green-50 dark:bg-green-900/20' : 'bg-red-50 dark:bg-red-900/20'
                                    }`}>
                                        <div className="flex items-center gap-2">
                                            {v.passed ? (
                                                <CheckCircle className="h-4 w-4 text-green-500" />
                                            ) : (
                                                <XCircle className="h-4 w-4 text-red-500" />
                                            )}
                                            <span className="font-medium text-slate-900 dark:text-white">{v.name}</span>
                                        </div>
                                        <span className={`text-sm ${v.passed ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                                            {v.message}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Settings Content */}
            {activeTab === 'settings' && (
            <>
            {/* Output Settings */}
            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <FileJson className="h-5 w-5" />
                    출력 설정
                </h3>
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            출력 포맷
                        </label>
                        <div className="flex gap-2">
                            {(['json', 'table', 'sarif'] as const).map((format) => (
                                <button
                                    key={format}
                                    onClick={() => updateConfig('outputFormat', format)}
                                    className={`px-4 py-2 rounded-lg border transition-colors ${config.outputFormat === format
                                        ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
                                        : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'
                                        }`}
                                >
                                    {format.toUpperCase()}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            스키마 버전
                        </label>
                        <select
                            value={config.schemaVersion}
                            onChange={(e) => updateConfig('schemaVersion', parseInt(e.target.value))}
                            className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                            <option value={1}>Version 1</option>
                            <option value={2}>Version 2 (권장)</option>
                        </select>
                    </div>
                </div>
            </div>

            {/* Scan Settings */}
            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <Settings className="h-5 w-5" />
                    스캔 설정
                </h3>
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            심각도 필터
                        </label>
                        <div className="flex flex-wrap gap-2">
                            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((severity) => (
                                <button
                                    key={severity}
                                    onClick={() => toggleSeverity(severity)}
                                    className={`px-3 py-1 rounded-lg border text-sm transition-colors ${config.severities.includes(severity)
                                        ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
                                        : 'border-slate-200 dark:border-slate-700 text-slate-500'
                                        }`}
                                >
                                    {severity}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            스캐너 유형
                        </label>
                        <div className="flex flex-wrap gap-2">
                            {[
                                { id: 'vuln', label: '취약점' },
                                { id: 'license', label: '라이선스' },
                                { id: 'misconfig', label: '설정 오류' },
                                { id: 'secret', label: '시크릿' },
                            ].map((scanner) => (
                                <button
                                    key={scanner.id}
                                    onClick={() => toggleScanner(scanner.id)}
                                    className={`px-3 py-1 rounded-lg border text-sm transition-colors ${config.scanners.includes(scanner.id)
                                        ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
                                        : 'border-slate-200 dark:border-slate-700 text-slate-500'
                                        }`}
                                >
                                    {scanner.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div className="flex items-center justify-between py-3 border-t border-slate-100 dark:border-slate-700">
                        <div>
                            <p className="font-medium text-slate-900 dark:text-white">수정사항 없는 취약점 무시</p>
                            <p className="text-sm text-slate-500">수정 버전이 없는 취약점을 결과에서 제외</p>
                        </div>
                        <button
                            onClick={() => updateConfig('ignoreUnfixed', !config.ignoreUnfixed)}
                            className={`relative w-12 h-6 rounded-full transition-colors ${config.ignoreUnfixed ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                                }`}
                        >
                            <span
                                className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${config.ignoreUnfixed ? 'translate-x-6' : ''
                                    }`}
                            />
                        </button>
                    </div>
                </div>
            </div>

            {/* Performance Settings */}
            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <Clock className="h-5 w-5" />
                    성능 설정
                </h3>
                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            타임아웃
                        </label>
                        <input
                            type="text"
                            value={config.timeout}
                            onChange={(e) => updateConfig('timeout', e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="10m"
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            캐시 경로
                        </label>
                        <input
                            type="text"
                            value={config.cacheDir}
                            onChange={(e) => updateConfig('cacheDir', e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="/tmp/trivy-cache"
                        />
                    </div>
                </div>
            </div>

            {/* Checkov Closed Network Settings */}
            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Checkov 폐쇄망 설정
                </h3>
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
                    일반 사용자 스캔 화면에서는 외부 모듈 다운로드 옵션을 제공하지 않습니다. 기본값은 차단이며,
                    사내 GitLab/Nexus/Terraform 모듈 미러처럼 폐쇄망 내부 저장소를 Checkov가 접근해야 하는 경우에만 시스템 관리자가 허용하세요.
                </div>
                <div className="mt-4 flex items-center justify-between py-3">
                    <div>
                        <p className="font-medium text-slate-900 dark:text-white">사내 모듈 저장소 사용 허용</p>
                        <p className="text-sm text-slate-500">
                            활성화한 경우에만 Checkov 명령어가 <code className="rounded bg-slate-100 px-1 dark:bg-slate-900">--download-external-modules true</code>를 사용할 수 있습니다.
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => updateCheckovConfig('allowInternalModuleDownload', !checkovConfig.allowInternalModuleDownload)}
                        className={`relative h-6 w-12 rounded-full transition-colors ${checkovConfig.allowInternalModuleDownload ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'}`}
                    >
                        <span
                            className={`absolute left-1 top-1 h-4 w-4 rounded-full bg-white transition-transform ${checkovConfig.allowInternalModuleDownload ? 'translate-x-6' : ''}`}
                        />
                    </button>
                </div>
            </div>

            {/* ZAP Settings */}
            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <Globe className="h-5 w-5" />
                    OWASP ZAP 웹 스캔 설정
                </h3>
                <div className="rounded-lg border border-orange-200 bg-orange-50 p-4 text-sm text-orange-800 dark:border-orange-800 dark:bg-orange-900/20 dark:text-orange-200">
                    ZAP은 별도 ZAP 서버 또는 컨테이너로 운영합니다. JASCA는 아래 URL로 ZAP API를 호출하고,
                    허용 대상 목록에 등록된 내부 URL만 스캔합니다.
                </div>

                <div className="mt-4 flex flex-wrap items-center gap-3">
                    <button
                        type="button"
                        onClick={testZapConnection}
                        disabled={zapConnectionMutation.isPending}
                        className="inline-flex items-center gap-2 rounded-lg border border-blue-300 px-3 py-2 text-sm font-medium text-blue-700 disabled:cursor-not-allowed disabled:opacity-60 dark:border-blue-800 dark:text-blue-300"
                    >
                        {zapConnectionMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
                        ZAP 연결 테스트
                    </button>
                    {zapConnectionMutation.data && <span className="text-sm text-green-600">연결됨: ZAP {zapConnectionMutation.data.version}</span>}
                    {zapConnectionMutation.error && <span className="text-sm text-red-600">연결 실패: {zapConnectionMutation.error.message}</span>}
                    <span className="text-xs text-slate-500">버전 조회만 수행하며 스캔은 실행하지 않습니다.</span>
                </div>

                <div className="mt-4 space-y-4">
                    <div className="flex items-center justify-between py-3">
                        <div>
                            <p className="font-medium text-slate-900 dark:text-white">ZAP 스캔 활성화</p>
                            <p className="text-sm text-slate-500">비활성화 상태에서는 사용자가 ZAP URL 스캔을 실행할 수 없습니다.</p>
                        </div>
                        <button
                            type="button"
                            onClick={() => updateZapConfig('enabled', !zapConfig.enabled)}
                            className={`relative h-6 w-12 rounded-full transition-colors ${zapConfig.enabled ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'}`}
                        >
                            <span className={`absolute left-1 top-1 h-4 w-4 rounded-full bg-white transition-transform ${zapConfig.enabled ? 'translate-x-6' : ''}`} />
                        </button>
                    </div>

                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">ZAP 서버 URL</label>
                            <input
                                type="url"
                                value={zapConfig.zapBaseUrl}
                                onChange={(e) => updateZapConfig('zapBaseUrl', e.target.value)}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                placeholder="http://zap-scanner:8080"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">ZAP API Key</label>
                            <input
                                type="password"
                                value={zapConfig.apiKey || ''}
                                onChange={(e) => updateZapConfig('apiKey', e.target.value)}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                placeholder={zapConfig.apiKeyConfigured ? '저장된 API Key 유지' : 'API Key가 없으면 비워두세요'}
                            />
                            {zapConfig.apiKeyConfigured && !zapConfig.apiKey && (
                                <p className="mt-1 text-xs text-green-600 dark:text-green-400">기존 API Key가 저장되어 있습니다. 비워두고 저장하면 기존 값이 유지됩니다.</p>
                            )}
                        </div>
                    </div>

                    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">연결 타임아웃(초)</label>
                            <input
                                type="number"
                                min={1}
                                value={zapConfig.connectTimeoutSeconds}
                                onChange={(e) => updateZapConfig('connectTimeoutSeconds', Number(e.target.value))}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">최대 스캔 시간(분)</label>
                            <input
                                type="number"
                                min={1}
                                value={zapConfig.maxScanDurationMinutes}
                                onChange={(e) => updateZapConfig('maxScanDurationMinutes', Number(e.target.value))}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">동시 스캔 수</label>
                            <input
                                type="number"
                                min={1}
                                value={zapConfig.maxConcurrentScans}
                                onChange={(e) => updateZapConfig('maxConcurrentScans', Number(e.target.value))}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                        </div>
                    </div>

                    <div className="grid grid-cols-1 gap-4">
                        <label className="flex items-start gap-3 rounded-lg border border-slate-200 p-3 dark:border-slate-700">
                            <input
                                type="checkbox"
                                checked={zapConfig.allowBaselineScan}
                                onChange={(e) => updateZapConfig('allowBaselineScan', e.target.checked)}
                                className="mt-1"
                            />
                            <span>
                                <span className="block font-medium text-slate-900 dark:text-white">Passive Spider 스캔 허용</span>
                                <span className="text-sm text-slate-500">허용된 URL을 탐색하고 Passive Alert만 수집합니다. 공격성 Active Scan은 제공하지 않습니다.</span>
                            </span>
                        </label>
                    </div>

                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">허용 대상 패턴</label>
                            <textarea
                                value={zapConfig.allowedTargetPatterns.join('\n')}
                                onChange={(e) => updateZapPatternList('allowedTargetPatterns', e.target.value)}
                                rows={5}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                placeholder={'*.internal\nhttps://app.koreacb.com'}
                            />
                            <p className="mt-1 text-xs text-slate-500">한 줄에 하나씩 입력합니다. 예: *.internal, https://app.koreacb.com</p>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">차단 대상 패턴</label>
                            <textarea
                                value={zapConfig.blockedTargetPatterns.join('\n')}
                                onChange={(e) => updateZapPatternList('blockedTargetPatterns', e.target.value)}
                                rows={5}
                                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                placeholder={'admin.internal\n*.prod.internal'}
                            />
                            <p className="mt-1 text-xs text-slate-500">허용 목록에 포함되어도 차단 목록에 걸리면 스캔이 거부됩니다.</p>
                        </div>
                    </div>

                    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
                        <div className="flex items-center justify-between gap-3">
                            <div>
                                <p className="font-medium text-slate-900 dark:text-white">ZAP 대상 프로필</p>
                                <p className="text-sm text-slate-500">사용자는 활성 프로필을 선택해야 하며, 전역 및 프로필 URL 정책을 모두 통과해야 합니다.</p>
                            </div>
                            <button
                                type="button"
                                onClick={addZapProfile}
                                className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white dark:bg-slate-100 dark:text-slate-900"
                            >
                                프로필 추가
                            </button>
                        </div>

                        <div className="mt-4 space-y-4">
                            {zapConfig.targetProfiles.map((profile) => (
                                <div key={profile.id} className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
                                    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                            프로필 이름
                                            <input value={profile.name} onChange={(e) => updateZapProfile(profile.id, { name: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-white" />
                                        </label>
                                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                            최대 실행 시간(분)
                                            <input type="number" min={1} max={zapConfig.maxScanDurationMinutes} value={profile.maxScanDurationMinutes} onChange={(e) => updateZapProfile(profile.id, { maxScanDurationMinutes: Number(e.target.value) })} className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-white" />
                                        </label>
                                        <div className="flex items-end justify-between gap-3">
                                            <label className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                                                <input type="checkbox" checked={profile.enabled} onChange={(e) => updateZapProfile(profile.id, { enabled: e.target.checked })} /> 활성화
                                            </label>
                                            <button type="button" onClick={() => updateZapConfig('targetProfiles', zapConfig.targetProfiles.filter((item) => item.id !== profile.id))} className="text-sm text-red-600">삭제</button>
                                        </div>
                                    </div>
                                    <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                            프로필 허용 URL 패턴
                                            <textarea value={profile.allowedTargetPatterns.join('\n')} onChange={(e) => updateZapProfilePatterns(profile.id, 'allowedTargetPatterns', e.target.value)} rows={3} placeholder="app.internal" className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-white" />
                                        </label>
                                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                            프로필 차단 URL 패턴
                                            <textarea value={profile.blockedTargetPatterns.join('\n')} onChange={(e) => updateZapProfilePatterns(profile.id, 'blockedTargetPatterns', e.target.value)} rows={3} placeholder="admin.app.internal" className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-white" />
                                        </label>
                                    </div>
                                </div>
                            ))}
                            {zapConfig.targetProfiles.length === 0 && <p className="text-sm text-slate-500">등록된 프로필이 없습니다. ZAP 스캔을 사용하려면 하나 이상 등록하세요.</p>}
                        </div>
                    </div>
                </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    {saved && (
                        <span className="flex items-center gap-2 text-green-600">
                            <CheckCircle className="h-5 w-5" />
                            저장됨
                        </span>
                    )}
                    {hasChanges && !saved && (
                        <span className="text-sm text-orange-600">변경사항 있음</span>
                    )}
                    {testResult === 'testing' && (
                        <span className="flex items-center gap-2 text-blue-600">
                            <Loader2 className="h-5 w-5 animate-spin" />
                            테스트 중...
                        </span>
                    )}
                    {testResult === 'success' && (
                        <span className="flex items-center gap-2 text-green-600">
                            <CheckCircle className="h-5 w-5" />
                            연결 성공
                        </span>
                    )}
                    {testResult === 'error' && (
                        <span className="flex items-center gap-2 text-red-600">
                            <AlertTriangle className="h-5 w-5" />
                            연결 실패
                        </span>
                    )}
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={handleReset}
                        className="flex items-center gap-2 px-4 py-2 text-sm border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                    >
                        <RotateCcw className="h-4 w-4" />
                        초기화
                    </button>
                    <button
                        onClick={handleTest}
                        disabled={testResult === 'testing'}
                        className="flex items-center gap-2 px-4 py-2 text-sm border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                    >
                        <Cpu className="h-4 w-4" />
                        테스트
                    </button>
                    <button
                        onClick={handleSave}
                        disabled={updateMutation.isPending || !hasChanges}
                        className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                    >
                        {updateMutation.isPending ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                            <Save className="h-4 w-4" />
                        )}
                        저장
                    </button>
                </div>
            </div>
            </>
            )}
        </div>
    );
}
