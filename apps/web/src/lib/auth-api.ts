import { useAuthStore } from '@/stores/auth-store';

const API_BASE = '/api';
const REQUEST_TIMEOUT = 30000;
const MAX_RETRIES = 3;
const RETRY_DELAY_BASE = 1000;

interface LoginRequest {
    email: string;
    password: string;
}

interface AuthResponse {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    requiresMfa?: boolean;
    mfaToken?: string;
    requiresEmailVerification?: boolean;
}

interface MfaVerifyRequest {
    mfaToken: string;
    code: string;
}

export class AuthApiError extends Error {
    constructor(
        message: string,
        public status: number = 0,
        public isRetryable: boolean = false
    ) {
        super(message);
        this.name = 'AuthApiError';
    }
}

function getRetryDelay(attempt: number): number {
    const delay = Math.min(RETRY_DELAY_BASE * Math.pow(2, attempt), 5000);
    return delay + Math.random() * 500;
}

async function safeParseJson(response: Response): Promise<any> {
    const text = await response.text();
    if (!text.trim()) return null;

    try {
        return JSON.parse(text);
    } catch {
        console.warn('[Auth API] Failed to parse response as JSON');
        return null;
    }
}

async function fetchWithTimeout(
    url: string,
    options: RequestInit,
    timeout: number = REQUEST_TIMEOUT
): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    } catch (error: any) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new AuthApiError('요청 시간이 초과되었습니다. 네트워크 연결을 확인해주세요.', 0, true);
        }
        throw error;
    }
}

async function fetchWithRetry(
    url: string,
    options: RequestInit,
    retryCount = 0
): Promise<Response> {
    try {
        const response = await fetchWithTimeout(url, options);

        if ([500, 502, 503, 504].includes(response.status) && retryCount < MAX_RETRIES) {
            const delay = getRetryDelay(retryCount);
            await new Promise((resolve) => setTimeout(resolve, delay));
            return fetchWithRetry(url, options, retryCount + 1);
        }

        return response;
    } catch (error: any) {
        if ((error instanceof TypeError || error instanceof AuthApiError) && retryCount < MAX_RETRIES) {
            const delay = getRetryDelay(retryCount);
            await new Promise((resolve) => setTimeout(resolve, delay));
            return fetchWithRetry(url, options, retryCount + 1);
        }
        throw error;
    }
}

class AuthApi {
    private getHeaders(): HeadersInit {
        const headers: HeadersInit = { 'Content-Type': 'application/json' };
        const token = useAuthStore.getState().accessToken;
        if (token) headers.Authorization = `Bearer ${token}`;
        return headers;
    }

    private async parseOrThrow<T>(
        response: Response,
        fallbackMessage: string
    ): Promise<T> {
        if (!response.ok) {
            const error = await safeParseJson(response);
            throw new AuthApiError(
                error?.message || fallbackMessage,
                response.status,
                response.status >= 500
            );
        }

        const result = await safeParseJson(response);
        if (!result) {
            throw new AuthApiError('서버 응답을 처리할 수 없습니다.', 500, true);
        }
        return result;
    }

    async login(data: LoginRequest): Promise<AuthResponse> {
        try {
            const response = await fetchWithRetry(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });

            return this.parseOrThrow<AuthResponse>(response, '로그인에 실패했습니다. 이메일과 비밀번호를 확인해주세요.');
        } catch (error: any) {
            if (error instanceof AuthApiError) throw error;
            if (error instanceof TypeError) {
                throw new AuthApiError('서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.', 0, true);
            }
            throw new AuthApiError(error.message || '로그인 중 오류가 발생했습니다.', 0, false);
        }
    }

    async verifyMfa(data: MfaVerifyRequest): Promise<AuthResponse> {
        try {
            const response = await fetchWithRetry(`${API_BASE}/auth/mfa/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });

            return this.parseOrThrow<AuthResponse>(response, 'MFA 인증에 실패했습니다. 코드를 확인해주세요.');
        } catch (error: any) {
            if (error instanceof AuthApiError) throw error;
            if (error instanceof TypeError) {
                throw new AuthApiError('서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.', 0, true);
            }
            throw new AuthApiError(error.message || 'MFA 인증 중 오류가 발생했습니다.', 0, false);
        }
    }

    async refresh(refreshToken: string): Promise<AuthResponse> {
        const response = await fetchWithRetry(`${API_BASE}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken }),
        });
        return this.parseOrThrow<AuthResponse>(response, '토큰 갱신에 실패했습니다.');
    }

    async logout(refreshToken: string): Promise<void> {
        try {
            await fetchWithTimeout(`${API_BASE}/auth/logout`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({ refreshToken }),
            }, 10000);
        } catch {
            console.warn('[Auth API] Logout request failed, clearing local state only');
        }
    }

    async getProfile(): Promise<any> {
        const response = await fetchWithRetry(`${API_BASE}/users/me`, {
            method: 'GET',
            headers: this.getHeaders(),
        });
        return this.parseOrThrow<any>(response, '프로필 정보를 가져오지 못했습니다.');
    }

    async getSessions(): Promise<any[]> {
        const response = await fetchWithRetry(`${API_BASE}/auth/sessions`, {
            method: 'GET',
            headers: this.getHeaders(),
        });
        return this.parseOrThrow<any[]>(response, '세션 목록을 가져오지 못했습니다.');
    }

    async revokeSession(sessionId: string): Promise<void> {
        const response = await fetchWithRetry(`${API_BASE}/auth/sessions/${sessionId}`, {
            method: 'DELETE',
            headers: this.getHeaders(),
        });
        if (!response.ok) {
            throw new AuthApiError('세션 취소에 실패했습니다.', response.status, response.status >= 500);
        }
    }

    async changePassword(currentPassword: string, newPassword: string): Promise<void> {
        const response = await fetchWithRetry(`${API_BASE}/auth/change-password`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ currentPassword, newPassword }),
        });

        if (!response.ok) {
            const error = await safeParseJson(response);
            throw new AuthApiError(
                error?.message || '비밀번호 변경에 실패했습니다.',
                response.status,
                response.status >= 500
            );
        }
    }

    async getLoginHistory(limit = 20, offset = 0): Promise<any[]> {
        const response = await fetchWithRetry(
            `${API_BASE}/auth/login-history?limit=${limit}&offset=${offset}`,
            {
                method: 'GET',
                headers: this.getHeaders(),
            }
        );
        return this.parseOrThrow<any[]>(response, '로그인 기록을 가져오지 못했습니다.');
    }

    async updateProfile(data: { name?: string }): Promise<any> {
        const response = await fetchWithRetry(`${API_BASE}/users/me`, {
            method: 'PUT',
            headers: this.getHeaders(),
            body: JSON.stringify(data),
        });
        return this.parseOrThrow<any>(response, '프로필 업데이트에 실패했습니다.');
    }

    async updateNotificationSettings(settings: {
        emailAlerts?: boolean;
        criticalOnly?: boolean;
        weeklyDigest?: boolean;
        scanComplete?: boolean;
        criticalVulns?: boolean;
        highVulns?: boolean;
        policyViolations?: boolean;
        exceptionAlerts?: boolean;
    }): Promise<any> {
        const response = await fetchWithRetry(`${API_BASE}/users/me/notification-settings`, {
            method: 'PUT',
            headers: this.getHeaders(),
            body: JSON.stringify(settings),
        });
        return this.parseOrThrow<any>(response, '알림 설정 업데이트에 실패했습니다.');
    }

    async getNotificationSettings(): Promise<{
        emailAlerts: boolean;
        criticalOnly: boolean;
        weeklyDigest: boolean;
        scanComplete: boolean;
        criticalVulns: boolean;
        highVulns: boolean;
        policyViolations: boolean;
        exceptionAlerts: boolean;
    }> {
        const defaults = {
            emailAlerts: true,
            criticalOnly: false,
            weeklyDigest: true,
            scanComplete: true,
            criticalVulns: true,
            highVulns: true,
            policyViolations: true,
            exceptionAlerts: true,
        };

        try {
            const response = await fetchWithRetry(`${API_BASE}/users/me/notification-settings`, {
                method: 'GET',
                headers: this.getHeaders(),
            });

            if (!response.ok) return defaults;
            return (await safeParseJson(response)) || defaults;
        } catch {
            return defaults;
        }
    }

    async getMfaStatus(): Promise<{ enabled: boolean }> {
        const response = await fetchWithRetry(`${API_BASE}/auth/mfa/status`, {
            method: 'GET',
            headers: this.getHeaders(),
        });
        return this.parseOrThrow<{ enabled: boolean }>(response, 'MFA 상태 조회에 실패했습니다.');
    }

    async setupMfa(): Promise<{ secret: string; qrCodeUrl: string }> {
        const response = await fetchWithRetry(`${API_BASE}/auth/mfa/setup`, {
            method: 'POST',
            headers: this.getHeaders(),
        });
        return this.parseOrThrow<{ secret: string; qrCodeUrl: string }>(response, 'MFA 설정에 실패했습니다.');
    }

    async enableMfa(code: string): Promise<{ success: boolean; message: string; backupCodes?: string[] }> {
        const response = await fetchWithRetry(`${API_BASE}/auth/mfa/enable`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ code }),
        });
        return this.parseOrThrow<{ success: boolean; message: string; backupCodes?: string[] }>(response, 'MFA 활성화에 실패했습니다.');
    }

    async disableMfa(code: string): Promise<{ success: boolean; message: string }> {
        const response = await fetchWithRetry(`${API_BASE}/auth/mfa/disable`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ code }),
        });
        return this.parseOrThrow<{ success: boolean; message: string }>(response, 'MFA 비활성화에 실패했습니다.');
    }

    async regenerateBackupCodes(code: string): Promise<{ success: boolean; backupCodes: string[] }> {
        const response = await fetchWithRetry(`${API_BASE}/auth/mfa/backup-codes`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ code }),
        });
        return this.parseOrThrow<{ success: boolean; backupCodes: string[] }>(response, '백업 코드 재생성에 실패했습니다.');
    }
}

export const authApi = new AuthApi();
