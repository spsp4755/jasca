'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { KeyRound, Loader2, Lock, Mail, Shield } from 'lucide-react';
import { useAuthStore } from '@/stores/auth-store';
import { authApi } from '@/lib/auth-api';

interface PublicSsoSettings {
    enabled: boolean;
    providers: {
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
    const {
        setUser,
        setTokens,
        setMfaRequired,
        setError,
        setLoading,
        isLoading,
        error,
        requiresMfa,
        mfaToken,
        accessToken,
        isAuthenticated,
    } = useAuthStore();

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState('');
    const [isCheckingAuth, setIsCheckingAuth] = useState(true);
    const [ssoSettings, setSsoSettings] = useState<PublicSsoSettings | null>(null);
    const [ssoLoading, setSsoLoading] = useState(true);

    useEffect(() => {
        const fetchSsoSettings = async () => {
            try {
                const response = await fetch('/api/settings/sso/public');
                if (response.ok) {
                    setSsoSettings(await response.json());
                }
            } catch (err) {
                console.error('Failed to fetch SSO settings:', err);
            } finally {
                setSsoLoading(false);
            }
        };

        fetchSsoSettings();
    }, []);

    useEffect(() => {
        if (isAuthenticated && accessToken) {
            router.replace('/dashboard');
            return;
        }

        setIsCheckingAuth(false);
    }, [isAuthenticated, accessToken, router]);

    if (isCheckingAuth && isAuthenticated) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
                <div className="text-center">
                    <Loader2 className="h-8 w-8 animate-spin text-blue-400 mx-auto mb-4" />
                    <p className="text-slate-400">대시보드로 이동 중입니다...</p>
                </div>
            </div>
        );
    }

    const handleSsoLogin = () => {
        window.location.href = '/api/auth/sso/keycloak?redirect=/dashboard';
    };

    const setAuthenticatedUser = (accessTokenValue: string, refreshTokenValue: string) => {
        setTokens(accessTokenValue, refreshTokenValue);

        const payload = JSON.parse(atob(accessTokenValue.split('.')[1]));
        setUser({
            id: payload.sub,
            email: payload.email,
            name: payload.email.split('@')[0],
            organizationId: payload.organizationId,
            roles: payload.roles || [],
        });
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

            setAuthenticatedUser(response.accessToken, response.refreshToken);
            router.push('/dashboard');
        } catch (err: any) {
            setError(err.message || '로그인에 실패했습니다.');
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
            setAuthenticatedUser(response.accessToken, response.refreshToken);
            router.push('/dashboard');
        } catch (err: any) {
            setError(err.message || 'MFA 인증에 실패했습니다.');
        } finally {
            setLoading(false);
        }
    };

    const keycloakEnabled = !ssoLoading && !!ssoSettings?.enabled && !!ssoSettings.providers?.keycloak;

    return (
        <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(37,99,235,0.25),_transparent_35%),linear-gradient(135deg,#020617,#0f172a_45%,#111827)] flex items-center justify-center p-4">
            <div className="w-full max-w-md">
                <div className="text-center mb-8">
                    <div className="inline-flex items-center gap-3 mb-4">
                        <Shield className="h-12 w-12 text-blue-400" />
                        <span className="text-3xl font-bold text-white">JASCA</span>
                    </div>
                    <p className="text-slate-400">폐쇄망 보안 취약점 관리 시스템</p>
                </div>

                <div className="bg-slate-900/75 backdrop-blur border border-slate-700/70 rounded-2xl p-8 shadow-2xl shadow-black/30">
                    <h2 className="text-2xl font-semibold text-white mb-2 text-center">
                        {requiresMfa ? 'MFA 인증' : '로그인'}
                    </h2>
                    <p className="text-sm text-slate-400 text-center mb-6">
                        사내 계정 또는 Keycloak SSO로 접속하세요.
                    </p>

                    {error && (
                        <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-lg text-red-300 text-sm">
                            {error}
                        </div>
                    )}

                    {!requiresMfa ? (
                        <>
                            {keycloakEnabled && (
                                <>
                                    <button
                                        type="button"
                                        onClick={handleSsoLogin}
                                        className="w-full mb-6 flex items-center justify-center gap-2 rounded-lg border border-blue-500/40 bg-blue-500/10 px-4 py-3 text-blue-100 hover:bg-blue-500/20 transition-colors"
                                    >
                                        <KeyRound className="h-5 w-5" />
                                        Keycloak SSO로 로그인
                                    </button>

                                    <div className="relative mb-6">
                                        <div className="absolute inset-0 flex items-center">
                                            <div className="w-full border-t border-slate-700" />
                                        </div>
                                        <div className="relative flex justify-center text-sm">
                                            <span className="px-2 bg-slate-900 text-slate-500">또는 로컬 계정</span>
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
                                            className="w-full bg-slate-950/70 border border-slate-600 rounded-lg pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
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
                                            className="w-full bg-slate-950/70 border border-slate-600 rounded-lg pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                            placeholder="비밀번호"
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
                                Authenticator 앱의 6자리 인증 코드를 입력하세요.
                            </p>
                            <input
                                type="text"
                                value={mfaCode}
                                onChange={(e) => setMfaCode(e.target.value)}
                                className="w-full bg-slate-950/70 border border-slate-600 rounded-lg px-4 py-3 text-white text-center text-2xl tracking-widest placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                placeholder="000000"
                                maxLength={6}
                                required
                            />

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
                </div>
            </div>
        </div>
    );
}
