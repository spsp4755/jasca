'use client';

import { useState } from 'react';
import {
    Link as LinkIcon,
    Plus,
    Copy,
    Trash2,
    CheckCircle,
    Github,
    GitBranch,
    Terminal,
    Eye,
    EyeOff,
    Loader2,
    AlertTriangle,
    Key,
} from 'lucide-react';
import { useApiTokens, useCreateApiToken } from '@/lib/api-hooks';

const cliExample = `# JASCA CLI 사용 예시

# 이미지 스캔
jasca scan --image backend-api:latest --project backend-api

# 결과 확인
jasca results --scan-id <SCAN_ID>

# 정책 검사
jasca policy-check --scan-id <SCAN_ID>`;

const pipelineExample = `# GitHub Actions 예시
- name: Scan with JASCA
  uses: jasca/action@v1
  with:
    image: \${{ env.IMAGE_NAME }}
    project: \${{ env.PROJECT_ID }}
    api-token: \${{ secrets.JASCA_TOKEN }}
    fail-on: critical`;

export default function CIIntegrationPage() {
    const { data: tokens = [], isLoading, error } = useApiTokens();
    const createTokenMutation = useCreateApiToken();

    const [showToken, setShowToken] = useState(false);
    const [selectedTab, setSelectedTab] = useState<'integrations' | 'cli' | 'pipeline'>('integrations');
    const [copied, setCopied] = useState(false);
    const [creatingToken, setCreatingToken] = useState(false);
    const [newToken, setNewToken] = useState<string | null>(null);

    // Get first CI/CD token or prompt to create one
    const ciToken = tokens.find(t => t.permissions.includes('scans:write')) || tokens[0];

    const handleCopy = async (text: string) => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleCreateCIToken = async () => {
        setCreatingToken(true);
        try {
            const result = await createTokenMutation.mutateAsync({
                name: 'CI/CD Pipeline Token',
                permissions: ['scans:read', 'scans:write', 'vulnerabilities:read', 'projects:read'],
                expiresIn: 365,
            });
            setNewToken(result.token);
        } catch (err) {
            console.error('Failed to create token:', err);
        } finally {
            setCreatingToken(false);
        }
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            </div>
        );
    }

    if (error) {
        return (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6 text-center">
                <AlertTriangle className="h-12 w-12 mx-auto text-red-500 mb-4" />
                <h3 className="text-lg font-semibold text-red-800 dark:text-red-200 mb-2">오류 발생</h3>
                <p className="text-red-600 dark:text-red-300">데이터를 불러오는데 실패했습니다.</p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white">CI/CD 연동</h1>
                <p className="text-slate-600 dark:text-slate-400 mt-1">
                    CI/CD 파이프라인과 JASCA를 연동합니다
                </p>
            </div>

            {/* Tabs */}
            <div className="border-b border-slate-200 dark:border-slate-700">
                <div className="flex gap-4">
                    {[
                        { id: 'integrations', label: '연동 현황' },
                        { id: 'cli', label: 'CLI 설정' },
                        { id: 'pipeline', label: '파이프라인 스니펫' },
                    ].map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setSelectedTab(tab.id as typeof selectedTab)}
                            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${selectedTab === tab.id
                                ? 'border-red-600 text-red-600'
                                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                }`}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Integrations Tab */}
            {selectedTab === 'integrations' && (
                <div className="space-y-4">
                    {/* API Tokens for CI/CD */}
                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                        <h3 className="font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                            <Key className="h-5 w-5" />
                            CI/CD용 API 토큰
                        </h3>

                        {newToken ? (
                            <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 mb-4">
                                <div className="flex items-center gap-2 mb-2">
                                    <CheckCircle className="h-5 w-5 text-green-600" />
                                    <p className="font-medium text-green-800 dark:text-green-200">새 토큰이 생성되었습니다!</p>
                                </div>
                                <div className="bg-white dark:bg-slate-900 rounded p-2 font-mono text-sm break-all">
                                    {showToken ? newToken : newToken.replace(/./g, '•')}
                                </div>
                                <div className="flex gap-2 mt-3">
                                    <button
                                        onClick={() => setShowToken(!showToken)}
                                        className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded hover:bg-slate-50 dark:hover:bg-slate-700"
                                    >
                                        {showToken ? '숨기기' : '보기'}
                                    </button>
                                    <button
                                        onClick={() => handleCopy(newToken)}
                                        className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700"
                                    >
                                        {copied ? '복사됨!' : '복사'}
                                    </button>
                                </div>
                                <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-3">
                                    ⚠️ 이 토큰은 다시 표시되지 않습니다. 안전하게 저장해주세요.
                                </p>
                            </div>
                        ) : ciToken ? (
                            <div className="flex items-center gap-4">
                                <div className="flex-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2">
                                    <p className="text-sm text-slate-500 mb-1">{ciToken.name}</p>
                                    <p className="font-mono text-sm">{ciToken.tokenPrefix}****</p>
                                </div>
                                <span className="px-3 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded text-sm">
                                    활성
                                </span>
                            </div>
                        ) : (
                            <div className="text-center py-6">
                                <Key className="h-12 w-12 mx-auto text-slate-300 dark:text-slate-600 mb-3" />
                                <p className="text-slate-600 dark:text-slate-400 mb-4">
                                    CI/CD 연동을 위한 API 토큰이 없습니다.
                                </p>
                                <button
                                    onClick={handleCreateCIToken}
                                    disabled={creatingToken}
                                    className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
                                >
                                    {creatingToken ? (
                                        <>
                                            <Loader2 className="h-4 w-4 animate-spin" />
                                            생성 중...
                                        </>
                                    ) : (
                                        <>
                                            <Plus className="h-4 w-4" />
                                            CI/CD 토큰 생성
                                        </>
                                    )}
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Integration Guide */}
                    <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                        <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">연동 가이드</h4>
                        <ol className="text-sm text-blue-700 dark:text-blue-300 space-y-1 list-decimal list-inside">
                            <li>위에서 API 토큰을 생성하거나 API 토큰 페이지에서 토큰을 가져옵니다.</li>
                            <li>CI/CD 환경의 시크릿에 <code className="bg-blue-100 dark:bg-blue-800 px-1 rounded">JASCA_TOKEN</code>으로 저장합니다.</li>
                            <li>파이프라인 스니펫 탭에서 설정 예제를 확인하세요.</li>
                        </ol>
                    </div>
                </div>
            )}

            {/* CLI Tab */}
            {selectedTab === 'cli' && (
                <div className="space-y-6">
                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                        <h3 className="font-semibold text-slate-900 dark:text-white mb-4">API 토큰</h3>
                        {ciToken ? (
                            <div className="flex items-center gap-2">
                                <input
                                    type="text"
                                    value={`${ciToken.tokenPrefix}****`}
                                    readOnly
                                    className="flex-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 font-mono text-sm"
                                />
                                <span className="text-sm text-slate-500">
                                    (API 토큰 페이지에서 전체 토큰 확인)
                                </span>
                            </div>
                        ) : (
                            <p className="text-slate-500">API 토큰 페이지에서 토큰을 먼저 생성하세요.</p>
                        )}
                    </div>

                    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                                <Terminal className="h-5 w-5" />
                                CLI 사용법
                            </h3>
                            <button
                                onClick={() => handleCopy(cliExample)}
                                className="text-sm text-blue-600 hover:text-blue-700"
                            >
                                {copied ? '복사됨!' : '복사'}
                            </button>
                        </div>
                        <pre className="bg-slate-900 text-green-400 rounded-lg p-4 text-sm overflow-x-auto">
                            {cliExample}
                        </pre>
                    </div>
                </div>
            )}

            {/* Pipeline Tab */}
            {selectedTab === 'pipeline' && (
                <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="font-semibold text-slate-900 dark:text-white">GitHub Actions 예시</h3>
                        <button
                            onClick={() => handleCopy(pipelineExample)}
                            className="text-sm text-blue-600 hover:text-blue-700"
                        >
                            {copied ? '복사됨!' : '복사'}
                        </button>
                    </div>
                    <pre className="bg-slate-900 text-slate-300 rounded-lg p-4 text-sm overflow-x-auto">
                        <code>{pipelineExample}</code>
                    </pre>
                </div>
            )}
        </div>
    );
}
