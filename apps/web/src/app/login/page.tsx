'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Shield, Mail, Lock, Loader2 } from 'lucide-react';
import { useAuthStore } from '@/stores/auth-store';
import { authApi } from '@/lib/auth-api';

// SSO Provider configs
const SsoProviderConfigs = {
    google: { name: 'Google', icon: '🔵', color: 'hover:bg-red-50 dark:hover:bg-red-900/20' },
    github: { name: 'GitHub', icon: '⚫', color: 'hover:bg-slate-100 dark:hover:bg-slate-700' },
    microsoft: { name: 'Microsoft', icon: '🟦', color: 'hover:bg-blue-50 dark:hover:bg-blue-900/20' },
    keycloak: { name: 'Keycloak', icon: '🔐', color: 'hover:bg-orange-50 dark:hover:bg-orange-900/20' },
};

interface PublicSsoSettings {
    enabled: boolean;
    providers: {
        google: boolean;
        github: boolean;
        microsoft: boolean;
        keycloak: boolean;
    };
    keycloakConfig?: {
        serverUrl: string;
        realm: string;
        clientId: string;
    };
}

export default function LoginPage() {
    const router = useRouter();
    const { setUser, setTokens, setMfaRequired, setError, setLoading, isLoading, error, requiresMfa, mfaToken, accessToken, isAuthenticated } = useAuthStore();

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState('');
    const [isCheckingAuth, setIsCheckingAuth] = useState(true);
    const [ssoSettings, setSsoSettings] = useState<PublicSsoSettings | null>(null);
    const [ssoLoading, setSsoLoading] = useState(true);

    const syncUserProfile = async (fallbackAccessToken: string) => {
        try {
            const profile = await authApi.getProfile();
            setUser({
                id: profile.id,
                email: profile.email,
                name: profile.name || profile.email?.split('@')[0] || 'User',
                organizationId: profile.organization?.id || profile.organizationId,
                roles: profile.roles || (profile.role ? [profile.role] : []),
                permissions: profile.permissions || [],
            });
            return;
        } catch (profileError) {
            console.warn('Failed to fetch profile after login, falling back to JWT payload', profileError);
        }

        const payload = JSON.parse(atob(fallbackAccessToken.split('.')[1]));
        setUser({
            id: payload.sub,
            email: payload.email,
            name: payload.email.split('@')[0],
            organizationId: payload.organizationId,
            roles: payload.roles || [],
            permissions: payload.permissions || [],
        });
    };

    // SSO 설정 조회
    useEffect(() => {
        const fetchSsoSettings = async () => {
            try {
                const response = await fetch('/api/settings/sso/public');
                if (response.ok) {
                    const data = await response.json();
                    setSsoSettings(data);
                }
            } catch (error) {
                console.error('Failed to fetch SSO settings:', error);
            } finally {
                setSsoLoading(false);
            }
        };
        fetchSsoSettings();
    }, []);

    // 이미 로그인된 상태라면 대시보드로 리다이렉트
    useEffect(() => {
        if (isAuthenticated && accessToken) {
            router.replace('/dashboard');
        } else {
            setIsCheckingAuth(false);
        }
    }, [isAuthenticated, accessToken, router]);

    // 인증 상태 확인 중에는 로딩 표시
    if (isCheckingAuth && isAuthenticated) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
                <div className="text-center">
                    <Loader2 className="h-8 w-8 animate-spin text-blue-400 mx-auto mb-4" />
                    <p className="text-slate-400">대시보드로 이동 중...</p>
                </div>
            </div>
        );
    }

    const handleSsoLogin = (providerId: string) => {
        // Redirect to SSO endpoint
        window.location.href = `/api/auth/sso/${providerId}?redirect=/dashboard`;
    };

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const response = await authApi.login({ email, password });

            if (response.requiresMfa && response.mfaToken) {
                setMfaRequired(response.mfaToken);
                setLoading(false);
                return;
            }

            setTokens(response.accessToken, response.refreshToken);
            await syncUserProfile(response.accessToken);

            router.push('/dashboard');
        } catch (err: any) {
            setError(err.message || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    const handleMfaVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!mfaToken) return;

        setError(null);
        setLoading(true);

        try {
            const response = await authApi.verifyMfa({ mfaToken, code: mfaCode });
            setTokens(response.accessToken, response.refreshToken);
            await syncUserProfile(response.accessToken);

            router.push('/dashboard');
        } catch (err: any) {
            setError(err.message || 'MFA verification failed');
        } finally {
            setLoading(false);
        }
    };

    // 활성화된 SSO providers 목록
    const enabledProviders = ssoSettings?.enabled
        ? Object.entries(ssoSettings.providers)
            .filter(([_, enabled]) => enabled)
            .map(([id]) => ({
                id,
                ...SsoProviderConfigs[id as keyof typeof SsoProviderConfigs],
            }))
        : [];

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
            <div className="w-full max-w-md">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center gap-3 mb-4">
                        <Shield className="h-12 w-12 text-blue-400" />
                        <span className="text-3xl font-bold text-white">JASCA</span>
                    </div>
                    <p className="text-slate-400">취약점 관리 시스템</p>
                </div>

                {/* Login Form */}
                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-8">
                    <h2 className="text-2xl font-semibold text-white mb-6 text-center">
                        {requiresMfa ? 'MFA 인증' : '로그인'}
                    </h2>

                    {error && (
                        <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-lg text-red-300 text-sm">
                            {error}
                        </div>
                    )}

                    {!requiresMfa ? (
                        <>
                            {/* SSO Options - 설정에 따라 조건부 렌더링 */}
                            {!ssoLoading && enabledProviders.length > 0 && (
                                <>
                                    <div className="space-y-3 mb-6">
                                        <p className="text-sm text-slate-400 text-center">SSO로 로그인</p>
                                        <div className={`grid gap-3 ${
                                            enabledProviders.length === 1 ? 'grid-cols-1' :
                                            enabledProviders.length === 2 ? 'grid-cols-2' :
                                            enabledProviders.length === 3 ? 'grid-cols-3' :
                                            'grid-cols-2 md:grid-cols-4'
                                        }`}>
                                            {enabledProviders.map((provider) => (
                                                <button
                                                    key={provider.id}
                                                    onClick={() => handleSsoLogin(provider.id)}
                                                    className={`flex flex-col items-center gap-1 p-3 border border-slate-600 rounded-lg transition-colors ${provider.color}`}
                                                >
                                                    <span className="text-xl">{provider.icon}</span>
                                                    <span className="text-xs text-slate-400">{provider.name}</span>
                                                </button>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="relative mb-6">
                                        <div className="absolute inset-0 flex items-center">
                                            <div className="w-full border-t border-slate-700" />
                                        </div>
                                        <div className="relative flex justify-center text-sm">
                                            <span className="px-2 bg-slate-800/50 text-slate-500">또는 이메일로 로그인</span>
                                        </div>
                                    </div>
                                </>
                            )}

                            <form onSubmit={handleLogin} className="space-y-5">
                                <div>
                                    <label className="block text-sm font-medium text-slate-300 mb-2">
                                        이메일
                                    </label>
                                    <div className="relative">
                                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500" />
                                        <input
                                            type="email"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            className="w-full bg-slate-900/50 border border-slate-600 rounded-lg pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                            placeholder="name@company.com"
                                            required
                                        />
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-slate-300 mb-2">
                                        비밀번호
                                    </label>
                                    <div className="relative">
                                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500" />
                                        <input
                                            type="password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            className="w-full bg-slate-900/50 border border-slate-600 rounded-lg pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                            placeholder="••••••••"
                                            required
                                        />
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={isLoading}
                                    className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                                >
                                    {isLoading ? (
                                        <>
                                            <Loader2 className="h-5 w-5 animate-spin" />
                                            로그인 중...
                                        </>
                                    ) : (
                                        '로그인'
                                    )}
                                </button>
                            </form>
                        </>
                    ) : (
                        <form onSubmit={handleMfaVerify} className="space-y-5">
                            <p className="text-slate-400 text-sm text-center mb-4">
                                Authenticator 앱에서 6자리 인증 코드를 입력하세요
                            </p>
                            <div>
                                <input
                                    type="text"
                                    value={mfaCode}
                                    onChange={(e) => setMfaCode(e.target.value)}
                                    className="w-full bg-slate-900/50 border border-slate-600 rounded-lg px-4 py-3 text-white text-center text-2xl tracking-widest placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="000000"
                                    maxLength={6}
                                    required
                                />
                            </div>

                            <button
                                type="submit"
                                disabled={isLoading}
                                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                            >
                                {isLoading ? (
                                    <>
                                        <Loader2 className="h-5 w-5 animate-spin" />
                                        확인 중...
                                    </>
                                ) : (
                                    '인증'
                                )}
                            </button>
                        </form>
                    )}

                    {!requiresMfa && (
                        <p className="mt-6 text-center text-slate-400 text-sm">
                            계정이 없으신가요?{' '}
                            <Link href="/register" className="text-blue-400 hover:text-blue-300">
                                회원가입
                            </Link>
                        </p>
                    )}
                </div>

                {/* Test accounts hint */}
                <div className="mt-6 text-center text-slate-500 text-xs">
                    <p>테스트 계정: admin@acme.com / admin123</p>
                </div>
            </div>
        </div>
    );
}

