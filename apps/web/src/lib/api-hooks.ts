'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '@/stores/auth-store';
import { toast } from '@/components/ui/toast';

const API_BASE = '/api';

// ============ Retry Configuration ============
const RETRY_CONFIG = {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 5000,
    timeout: 30000,
};

// ============ Custom Error Class ============
export class ApiError extends Error {
    constructor(
        message: string,
        public status: number,
        public isRetryable: boolean = false,
        public isNetworkError: boolean = false
    ) {
        super(message);
        this.name = 'ApiError';
    }
}

// ============ Token Refresh ============
let isRefreshing = false;
let refreshPromise: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
    // 이미 갱신 중이면 기존 Promise 반환
    if (isRefreshing && refreshPromise) {
        return refreshPromise;
    }

    const { refreshToken, setTokens, logout } = useAuthStore.getState();
    if (!refreshToken) {
        logout();
        return false;
    }

    isRefreshing = true;
    refreshPromise = (async () => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            
            const response = await fetch('/api/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refreshToken }),
                signal: controller.signal,
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const data = await response.json();
                setTokens(data.accessToken, data.refreshToken);
                return true;
            }
            
            // 401 또는 403 - refresh token도 만료됨
            if (response.status === 401 || response.status === 403) {
                logout();
                return false;
            }
            
            return false;
        } catch (error) {
            console.error('[Auth] Token refresh failed:', error);
            return false;
        } finally {
            isRefreshing = false;
            refreshPromise = null;
        }
    })();

    return refreshPromise;
}

// ============ Retry Delay Calculation ============
function getRetryDelay(attempt: number): number {
    const delay = Math.min(
        RETRY_CONFIG.baseDelay * Math.pow(2, attempt),
        RETRY_CONFIG.maxDelay
    );
    // 지터 추가하여 thundering herd 방지
    return delay + Math.random() * 500;
}

// ============ Safe JSON Parse ============
async function safeParseJson(response: Response): Promise<any> {
    const text = await response.text();
    if (!text || text.trim() === '') {
        return null;
    }
    try {
        return JSON.parse(text);
    } catch {
        // HTML 응답이나 잘못된 형식인 경우
        console.warn('[API] Failed to parse response as JSON:', text.substring(0, 100));
        return null;
    }
}

// ============ Main Auth Fetch Function ============
async function authFetch(url: string, options: RequestInit = {}, retryCount = 0): Promise<any> {
    const token = useAuthStore.getState().accessToken;
    const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
    const headers: HeadersInit = {
        ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
        ...(options.headers || {}),
    };
    if (token) {
        (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
    }
    
    // AbortController로 타임아웃 구현
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), RETRY_CONFIG.timeout);
    
    try {
        const response = await fetch(url, { 
            ...options, 
            headers,
            signal: controller.signal 
        });
        clearTimeout(timeoutId);
        
        // ========== 401 Unauthorized ==========
        // 토큰 갱신 시도 후 재요청
        if (response.status === 401 && retryCount === 0) {
            console.log('[API] 401 received, attempting token refresh...');
            const refreshed = await refreshAccessToken();
            if (refreshed) {
                console.log('[API] Token refreshed, retrying request...');
                return authFetch(url, options, 1);
            }
            const errorMsg = '인증이 만료되었습니다. 다시 로그인해주세요.';
            toast.error('인증 오류', errorMsg);
            throw new ApiError(
                errorMsg,
                401,
                false,
                false
            );
        }
        
        // ========== 5xx Server Errors ==========
        // 재시도 가능한 서버 에러 (500, 502, 503, 504)
        if ([500, 502, 503, 504].includes(response.status)) {
            if (retryCount < RETRY_CONFIG.maxRetries) {
                const delay = getRetryDelay(retryCount);
                console.log(`[API] ${response.status} error, retrying in ${Math.round(delay)}ms... (attempt ${retryCount + 1}/${RETRY_CONFIG.maxRetries})`);
                await new Promise(r => setTimeout(r, delay));
                return authFetch(url, options, retryCount + 1);
            }
            
            const errorData = await safeParseJson(response);
            throw new ApiError(
                errorData?.message || '서버에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도해주세요.',
                response.status,
                true,
                false
            );
        }
        
        if (!response.ok) {
            const errorData = await safeParseJson(response);
            // Handle array of messages (validation errors)
            let errorMessage = '';
            if (Array.isArray(errorData?.message)) {
                errorMessage = errorData.message.join(', ');
            } else {
                errorMessage = errorData?.message || getDefaultErrorMessage(response.status);
            }
            
            // Show toast notification for all client errors (4xx)
            if (response.status >= 400 && response.status < 500) {
                const errorTitle = response.status === 400 ? '요청 오류' :
                                   response.status === 403 ? '권한 오류' :
                                   response.status === 404 ? '리소스 없음' :
                                   response.status === 409 ? '중복 오류' :
                                   'API 오류';
                toast.error(errorTitle, errorMessage);
            }
            
            throw new ApiError(
                errorMessage,
                response.status,
                response.status >= 500,
                false
            );
        }
        
        // ========== Success Response ==========
        return await safeParseJson(response);
        
    } catch (error: any) {
        clearTimeout(timeoutId);
        
        // ApiError는 그대로 전파
        if (error instanceof ApiError) {
            throw error;
        }
        
        // ========== AbortError (Timeout) ==========
        if (error.name === 'AbortError') {
            if (retryCount < RETRY_CONFIG.maxRetries) {
                const delay = getRetryDelay(retryCount);
                console.log(`[API] Request timeout, retrying in ${Math.round(delay)}ms... (attempt ${retryCount + 1}/${RETRY_CONFIG.maxRetries})`);
                await new Promise(r => setTimeout(r, delay));
                return authFetch(url, options, retryCount + 1);
            }
            throw new ApiError(
                '요청 시간이 초과되었습니다. 네트워크 연결을 확인해주세요.',
                0,
                true,
                true
            );
        }
        
        // ========== Network Error (fetch failed) ==========
        if (error instanceof TypeError && (error.message.includes('fetch') || error.message.includes('network'))) {
            if (retryCount < RETRY_CONFIG.maxRetries) {
                const delay = getRetryDelay(retryCount);
                console.log(`[API] Network error, retrying in ${Math.round(delay)}ms... (attempt ${retryCount + 1}/${RETRY_CONFIG.maxRetries})`);
                await new Promise(r => setTimeout(r, delay));
                return authFetch(url, options, retryCount + 1);
            }
            throw new ApiError(
                '서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.',
                0,
                true,
                true
            );
        }
        
        // ========== Unknown Error ==========
        console.error('[API] Unexpected error:', error);
        throw new ApiError(
            error.message || '알 수 없는 오류가 발생했습니다.',
            0,
            false,
            false
        );
    }
}

// ============ Default Error Messages ============
function getDefaultErrorMessage(status: number): string {
    switch (status) {
        case 400:
            return '잘못된 요청입니다.';
        case 401:
            return '인증이 필요합니다.';
        case 403:
            return '접근 권한이 없습니다.';
        case 404:
            return '요청한 리소스를 찾을 수 없습니다.';
        case 409:
            return '중복된 데이터가 존재합니다.';
        case 422:
            return '입력 데이터가 유효하지 않습니다.';
        case 429:
            return '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.';
        case 500:
            return '서버 내부 오류가 발생했습니다.';
        case 502:
            return '서버 연결에 문제가 발생했습니다.';
        case 503:
            return '서비스를 일시적으로 사용할 수 없습니다.';
        case 504:
            return '서버 응답 시간이 초과되었습니다.';
        default:
            return '요청 처리에 실패했습니다.';
    }
}


// ============ Scans API ============

export interface Scan {
    id: string;
    projectId: string;
    scanType: string;
    targetName: string;
    scanLocation?: string;
    imageRef?: string;
    imageDigest?: string;
    artifactName?: string;
    artifactType?: string;
    sourceType?: string;
    status: string;
    startedAt: string;
    completedAt?: string;
    createdAt?: string;
    summary?: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        unknown?: number;
        total?: number;
    };
    scanEvidence?: {
        completed?: boolean;
        startedAt?: string;
        completedAt?: string;
        durationMs?: number;
        originalFileName?: string;
        fileSizeBytes?: number;
        scanMode?: string;
        archiveType?: string | null;
        targetKind?: string;
        inputKind?: string;
        cacheDir?: string;
        scanner?: string;
        command?: string;
        options?: {
            scanners?: string[];
            severities?: string[];
            offlineScan?: boolean;
            skipDbUpdate?: boolean;
            skipJavaDbUpdate?: boolean;
            ignoreUnfixed?: boolean;
            timeout?: string;
            analysisStrategy?: string;
            rpmOsFamily?: string;
            rpmOsVersion?: string;
            frameworks?: string[] | string;
            checks?: string[] | string;
            skipChecks?: string[] | string;
            downloadExternalModules?: boolean;
        };
        commands?: Array<{ phase: string; command: string }>;
        resultSummary?: {
            resultCount?: number;
            vulnerabilities?: number;
            packages?: number;
            licenses?: number;
            misconfigurations?: number;
            secrets?: number;
            targets?: Array<{
                target?: string;
                class?: string;
                type?: string;
                vulnerabilities?: number;
                packages?: number;
                licenses?: number;
                misconfigurations?: number;
                secrets?: number;
            }>;
        };
    } | null;
    project?: {
        name: string;
    };
    artifacts?: Array<{
        id: string;
        type: 'CYCLONEDX_JSON';
        sha256: string;
        generator: string;
        generatorVersion?: string | null;
        createdAt: string;
    }>;
}

export function useScans(projectId?: string) {
    return useQuery<{ results: Scan[]; total: number }>({
        queryKey: ['scans', projectId],
        queryFn: () => {
            const params = new URLSearchParams();
            if (projectId) params.set('projectId', projectId);
            params.set('limit', '50');
            return authFetch(`${API_BASE}/scans?${params.toString()}`);
        },
    });
}

export function useScan(id: string) {
    return useQuery<Scan>({
        queryKey: ['scan', id],
        queryFn: () => authFetch(`${API_BASE}/scans/${id}`),
        enabled: !!id,
    });
}

// Upload scan DTO interface
export interface UploadScanDto {
    sourceType: 'TRIVY_JSON' | 'TRIVY_SARIF' | 'CHECKOV_JSON' | 'ZAP_JSON' | 'SARIF' | 'CI_BAMBOO' | 'CI_GITLAB' | 'CI_JENKINS' | 'CI_GITHUB_ACTIONS' | 'MANUAL';
    projectName?: string;
    organizationId?: string;
    imageRef?: string;
    imageDigest?: string;
    tag?: string;
    commitHash?: string;
    branch?: string;
    ciPipeline?: string;
    ciJobUrl?: string;
}

export interface TrivyScanOptions {
    scanMode?: 'auto' | 'fs' | 'rootfs' | 'image' | 'repo' | 'sbom' | 'vm' | 'rpm';
    analysisStrategy?: 'auto' | 'direct' | 'syft-sbom';
    rpmOsFamily?: string;
    rpmOsVersion?: string;
    offlineScan?: boolean;
    skipDbUpdate?: boolean;
    skipJavaDbUpdate?: boolean;
    ignoreUnfixed?: boolean;
    severities?: string[];
    scanners?: string[];
    timeout?: string;
}

export interface CheckovScanOptions {
    frameworks?: string[];
    checks?: string[];
    skipChecks?: string[];
    quiet?: boolean;
    timeout?: string;
}

export interface SemgrepScanUiOptions {
    profile?: 'all' | 'security' | 'custom-only';
    languages?: string[];
    incremental?: boolean;
    timeout?: string;
}

export interface ZapScanRequest {
    projectId?: string;
    targetUrl: string;
    scanMode: 'baseline' | 'passive' | 'active';
    confirmActiveScan?: boolean;
    authentication?: {
        type: 'none' | 'cookie' | 'authorization';
        value?: string;
    };
    projectName?: string;
    organizationId?: string;
    imageRef?: string;
    tag?: string;
    scanOperationId?: string;
    targetProfileId?: string;
}

export function useUploadScan() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({
            projectId,
            file,
            metadata,
            scanTarget,
            scanner,
            trivyOptions,
            checkovOptions,
            semgrepOptions,
            scanOperationId,
            signal,
        }: {
            projectId?: string; // Now optional - can use projectName + organizationId in metadata instead
            file: File;
            metadata: UploadScanDto;
            scanTarget?: boolean;
            scanner?: 'trivy' | 'checkov' | 'semgrep';
            trivyOptions?: TrivyScanOptions;
            checkovOptions?: CheckovScanOptions;
            semgrepOptions?: SemgrepScanUiOptions;
            scanOperationId?: string;
            signal?: AbortSignal;
        }) => {
            const token = useAuthStore.getState().accessToken;
            const formData = new FormData();
            formData.append('file', file);
            // Append metadata fields
            Object.entries(metadata).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    formData.append(key, String(value));
                }
            });

            if (scanTarget && scanner) {
                formData.append('scanner', scanner);
            }

            if (scanTarget && trivyOptions) {
                Object.entries(trivyOptions).forEach(([key, value]) => {
                    if (value === undefined || value === null) return;
                    formData.append(key, Array.isArray(value) ? value.join(',') : String(value));
                });
            }

            if (scanTarget && checkovOptions) {
                Object.entries(checkovOptions).forEach(([key, value]) => {
                    if (value === undefined || value === null) return;
                    formData.append(key, Array.isArray(value) ? value.join(',') : String(value));
                });
            }

            if (scanTarget && semgrepOptions) {
                if (semgrepOptions.profile) formData.append('semgrepProfile', semgrepOptions.profile);
                if (semgrepOptions.languages?.length) formData.append('semgrepLanguages', semgrepOptions.languages.join(','));
                if (semgrepOptions.incremental) formData.append('semgrepIncremental', 'true');
                if (semgrepOptions.timeout) formData.append('timeout', semgrepOptions.timeout);
            }

            if (scanTarget && scanOperationId) {
                formData.append('scanOperationId', scanOperationId);
            }

            const endpoint = scanTarget ? 'scan/file' : 'upload/file';
            const url = projectId
                ? `${API_BASE}/scans/${endpoint}?projectId=${projectId}`
                : `${API_BASE}/scans/${endpoint}`;

            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
                body: formData,
                signal,
            });

            if (!response.ok) {
                const responseText = await response.text().catch(() => '');
                let message = response.status === 413
                    ? '업로드 파일이 설정된 최대 크기를 초과했습니다. TRIVY_UPLOAD_MAX_BYTES와 앞단 reverse proxy 업로드 제한을 확인하세요.'
                    : 'Upload failed';

                if (responseText) {
                    try {
                        const error = JSON.parse(responseText);
                        message = error.message || message;
                    } catch {
                        message = responseText.slice(0, 500) || message;
                    }
                }

                throw new Error(message);
            }

            return response.json();
        },
        onSuccess: () => {
            // Use exact:false to invalidate all queries starting with 'scans' regardless of projectId
            queryClient.invalidateQueries({ queryKey: ['scans'], exact: false });
            queryClient.invalidateQueries({ queryKey: ['project-scans'], exact: false });
            queryClient.invalidateQueries({ queryKey: ['projects'], exact: false });
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
            queryClient.refetchQueries({ queryKey: ['notifications'] });
        },
    });
}

export function useCancelTrivyScan() {
    return useMutation({
        mutationFn: (operationId: string) =>
            authFetch(`${API_BASE}/scans/scan/cancel/${operationId}`, {
                method: 'POST',
            }),
    });
}

// ============ Vulnerabilities API ============

export interface Vulnerability {
    id: string;
    cveId: string;
    pkgName: string;
    installedVersion: string;
    fixedVersion?: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    status: 'OPEN' | 'ASSIGNED' | 'IN_PROGRESS' | 'FIX_SUBMITTED' | 'VERIFYING' | 'FIXED' | 'CLOSED' | 'IGNORED' | 'FALSE_POSITIVE';
    title: string;
    description?: string;
    cweIds?: string[];
    assigneeId?: string;
    assignee?: {
        name: string;
        email: string;
    };
    scanResult?: {
        project?: {
            name: string;
        };
    };
    createdAt?: string;
    updatedAt?: string;
}

export interface VulnerabilitiesFilter {
    projectId?: string;
    severity?: string[];
    status?: string[];
    search?: string;
    page?: number;
    pageSize?: number;
    sortBy?: 'severity' | 'cveId' | 'pkgName' | 'status' | 'createdAt';
    sortOrder?: 'asc' | 'desc';
    latestScanOnly?: boolean;
}

export function useVulnerabilities(filters?: VulnerabilitiesFilter) {
    return useQuery<{ results: Vulnerability[]; total: number }>({
        queryKey: ['vulnerabilities', filters],
        queryFn: async () => {
            const params = new URLSearchParams();
            if (filters?.projectId) params.set('projectId', filters.projectId);
            if (filters?.severity?.length) {
                filters.severity.forEach(s => params.append('severity', s));
            }
            if (filters?.status?.length) {
                filters.status.forEach(s => params.append('status', s));
            }
            // Server-side search: use cveId and pkgName filters
            if (filters?.search) {
                params.set('cveId', filters.search);
                params.set('pkgName', filters.search);
            }
            // Server-side pagination
            const page = filters?.page || 1;
            const pageSize = filters?.pageSize || 25;
            params.set('limit', String(pageSize));
            params.set('offset', String((page - 1) * pageSize));
            // Server-side sorting
            if (filters?.sortBy) {
                params.set('sortBy', filters.sortBy);
                params.set('sortOrder', filters?.sortOrder || 'asc');
            }
            // Latest scan only filter
            if (filters?.latestScanOnly) {
                params.set('latestScanOnly', 'true');
            }
            const response = await authFetch(`${API_BASE}/vulnerabilities?${params.toString()}`);

            
            // Transform API response: flatten vulnerability relation data
            // API returns scanVulnerability with nested vulnerability object
            // Frontend expects flattened data with cveId, severity, title, description at top level
            const transformedResults = (response.results || []).map((item: any) => ({
                id: item.id,
                // Map from nested vulnerability object
                cveId: item.vulnerability?.cveId || item.cveId || 'Unknown',
                severity: item.vulnerability?.severity || item.severity || 'UNKNOWN',
                title: item.vulnerability?.title || item.title || '',
                description: item.vulnerability?.description || item.description || '',
                // Direct fields from scanVulnerability
                pkgName: item.pkgName || '',
                installedVersion: item.pkgVersion || item.installedVersion || '',
                fixedVersion: item.fixedVersion || '',
                status: item.status || 'OPEN',
                assigneeId: item.assigneeId,
                assignee: item.assignee,
                scanResult: item.scanResult,
                createdAt: item.createdAt,
                updatedAt: item.updatedAt,
            }));

            return {
                results: transformedResults,
                total: response.total || transformedResults.length,
            };
        },
    });
}

export function useVulnerability(id: string) {
    return useQuery<Vulnerability>({
        queryKey: ['vulnerability', id],
        queryFn: async () => {
            const item = await authFetch(`${API_BASE}/vulnerabilities/${id}`);
            
            // Transform API response: flatten vulnerability relation data
            return {
                id: item.id,
                // Map from nested vulnerability object
                cveId: item.vulnerability?.cveId || item.cveId || 'Unknown',
                severity: item.vulnerability?.severity || item.severity || 'UNKNOWN',
                title: item.vulnerability?.title || item.title || '',
                description: item.vulnerability?.description || item.description || '',
                cweIds: item.vulnerability?.cweIds || item.cweIds || [],
                // Direct fields from scanVulnerability
                pkgName: item.pkgName || '',
                installedVersion: item.pkgVersion || item.installedVersion || '',
                fixedVersion: item.fixedVersion || '',
                status: item.status || 'OPEN',
                assigneeId: item.assigneeId,
                assignee: item.assignee,
                scanResult: item.scanResult,
                createdAt: item.createdAt,
                updatedAt: item.updatedAt,
            };
        },
        enabled: !!id,
    });
}

export function useUpdateVulnerabilityStatus() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, status }: { id: string; status: string }) =>
            authFetch(`${API_BASE}/vulnerabilities/${id}/status`, {
                method: 'PUT',
                body: JSON.stringify({ status }),
            }),
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
            queryClient.invalidateQueries({ queryKey: ['vulnerability', variables.id] });
            queryClient.invalidateQueries({ queryKey: ['vulnerability-history', variables.id] });
            queryClient.invalidateQueries({ queryKey: ['available-transitions', variables.id] });
        },
    });
}

// Available transitions for workflow management
export interface AvailableTransition {
    status: string;
    name: string;
    requiresRole?: string;
}

export function useAvailableTransitions(vulnerabilityId: string) {
    return useQuery<AvailableTransition[]>({
        queryKey: ['available-transitions', vulnerabilityId],
        queryFn: () => authFetch(`${API_BASE}/vulnerabilities/${vulnerabilityId}/available-transitions`),
        enabled: !!vulnerabilityId,
        staleTime: 30000, // 30 seconds cache
    });
}

export function useAssignVulnerability() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, assigneeId }: { id: string; assigneeId: string | null }) =>
            authFetch(`${API_BASE}/vulnerabilities/${id}/assign`, {
                method: 'PUT',
                body: JSON.stringify({ assigneeId }),
            }),
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
            queryClient.invalidateQueries({ queryKey: ['vulnerability', variables.id] });
        },
    });
}

export function useAddVulnerabilityComment() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, content }: { id: string; content: string }) =>
            authFetch(`${API_BASE}/vulnerabilities/${id}/comments`, {
                method: 'POST',
                body: JSON.stringify({ content }),
            }),
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: ['vulnerability-history', variables.id] });
        },
    });
}

export interface VulnerabilityHistoryItem {
    id: string;
    type: 'status_change' | 'comment' | 'discovery';
    action: string;
    from?: string;
    to?: string;
    content?: string;
    user: string;
    userId: string;
    comment?: string;
    date: string;
}

export function useVulnerabilityHistory(id: string) {
    return useQuery<VulnerabilityHistoryItem[]>({
        queryKey: ['vulnerability-history', id],
        queryFn: () => authFetch(`${API_BASE}/vulnerabilities/${id}/history`),
        enabled: !!id,
    });
}

// ============ Scan Diff API ============

export interface ScanDiff {
    baseScan: {
        id: string;
        targetName: string;
        date: string;
        totalVulnerabilities: number;
    };
    compareScan: {
        id: string;
        targetName: string;
        date: string;
        totalVulnerabilities: number;
    };
    added: Array<{
        cveId: string;
        pkgName: string;
        severity: string;
        title: string;
        fixedVersion?: string;
    }>;
    removed: Array<{
        cveId: string;
        pkgName: string;
        severity: string;
        title: string;
        fixedVersion?: string;
    }>;
    unchanged: number;
}

export function useScanDiff(baseScanId: string, compareScanId: string) {
    return useQuery<ScanDiff>({
        queryKey: ['scan-diff', baseScanId, compareScanId],
        queryFn: () => authFetch(`${API_BASE}/scans/${baseScanId}/compare/${compareScanId}`),
        enabled: !!baseScanId && !!compareScanId,
    });
}

// ============ Policies API ============

export interface Policy {
    id: string;
    name: string;
    description?: string;
    isActive: boolean;
    organizationId?: string;
    projectId?: string;
    rules: PolicyRule[];
    organization?: { id: string; name: string };
    project?: { id: string; name: string };
    createdAt: string;
    updatedAt: string;
}


export interface PolicyRule {
    id?: string;
    ruleType: string;
    operator?: string;
    condition?: string;
    conditions?: Record<string, any>;
    value?: string;
    action: string;
    message?: string;
    sendNotification?: boolean;
}

export interface PolicyEvaluationResult {
    allowed: boolean;
    blockedBy?: { policyId: string; policyName: string; ruleId: string };
    violations: Array<{
        policyId: string;
        policyName: string;
        ruleId: string;
        ruleName: string;
        action: string;
        message?: string;
        severity: string;
        count: number;
        cveIds: string[];
    }>;
    warnings: Array<{
        policyId: string;
        policyName: string;
        ruleId: string;
        ruleName: string;
        action: string;
        message?: string;
        severity: string;
        count: number;
        cveIds: string[];
    }>;
    appliedExceptions: Array<{
        id: string;
        exceptionType: string;
        targetValue: string;
        status: string;
        expiresAt?: string | null;
    }>;
}

export function usePolicies(organizationId?: string, projectId?: string) {
    return useQuery<Policy[]>({
        queryKey: ['policies', organizationId, projectId],
        queryFn: () => {
            const params = new URLSearchParams();
            if (organizationId) params.set('organizationId', organizationId);
            if (projectId) params.set('projectId', projectId);
            return authFetch(`${API_BASE}/policies?${params.toString()}`);
        },
    });
}

export function usePolicy(id: string) {
    return useQuery<Policy>({
        queryKey: ['policy', id],
        queryFn: () => authFetch(`${API_BASE}/policies/${id}`),
        enabled: !!id,
    });
}

export function useCreatePolicy() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: Partial<Policy>) =>
            authFetch(`${API_BASE}/policies`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['policies'] });
        },
    });
}

export function useUpdatePolicy() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: string } & Partial<Policy>) =>
            authFetch(`${API_BASE}/policies/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['policies'] });
        },
    });
}

export function useDeletePolicy() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/policies/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['policies'] });
        },
    });
}

export function usePolicyEvaluation(projectId?: string, scanResultId?: string) {
    return useQuery<PolicyEvaluationResult>({
        queryKey: ['policy-evaluation', projectId, scanResultId],
        enabled: !!projectId && !!scanResultId,
        queryFn: () =>
            authFetch(`${API_BASE}/policies/evaluate`, {
                method: 'POST',
                body: JSON.stringify({ projectId, scanResultId }),
            }),
    });
}

// ============ Manual Advisories API ============

export interface ManualAdvisory {
    id: string;
    advisoryId: string;
    cveId?: string | null;
    title: string;
    description?: string | null;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    packageName: string;
    affectedVersionRange: string;
    fixedVersion?: string | null;
    remediation?: string | null;
    references: string[];
    isActive: boolean;
    organizationId?: string | null;
    projectId?: string | null;
    organization?: { id: string; name: string };
    project?: { id: string; name: string };
    createdAt: string;
    updatedAt: string;
}

export interface ManualAdvisoryInput {
    advisoryId: string;
    cveId?: string;
    title: string;
    description?: string;
    severity: ManualAdvisory['severity'];
    packageName: string;
    affectedVersionRange?: string;
    fixedVersion?: string;
    remediation?: string;
    references?: string[];
    isActive?: boolean;
    organizationId?: string;
    projectId?: string;
}

export function useManualAdvisories(filters?: { organizationId?: string; projectId?: string; isActive?: boolean }) {
    return useQuery<ManualAdvisory[]>({
        queryKey: ['manual-advisories', filters],
        queryFn: () => {
            const params = new URLSearchParams();
            if (filters?.organizationId) params.set('organizationId', filters.organizationId);
            if (filters?.projectId) params.set('projectId', filters.projectId);
            if (filters?.isActive !== undefined) params.set('isActive', String(filters.isActive));
            const query = params.toString();
            return authFetch(`${API_BASE}/manual-advisories${query ? `?${query}` : ''}`);
        },
    });
}

export function useCreateManualAdvisory() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: ManualAdvisoryInput) =>
            authFetch(`${API_BASE}/manual-advisories`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['manual-advisories'] });
        },
    });
}

export function useBulkUploadManualAdvisories() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (file: File) => {
            const formData = new FormData();
            formData.append('file', file);
            return authFetch(`${API_BASE}/manual-advisories/upload`, {
                method: 'POST',
                body: formData,
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['manual-advisories'] });
        },
    });
}

export function useUpdateManualAdvisory() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: string } & Partial<ManualAdvisoryInput>) =>
            authFetch(`${API_BASE}/manual-advisories/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['manual-advisories'] });
        },
    });
}

export function useDeleteManualAdvisory() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/manual-advisories/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['manual-advisories'] });
        },
    });
}

// ============ Projects API ============

export interface Project {
    id: string;
    name: string;
    slug: string;
    description?: string;
    organizationId: string;
    createdAt: string;
    updatedAt: string;
    // Extended fields
    stats?: {
        totalScans: number;
        lastScanAt?: string;
        vulnerabilities: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            total: number;
        };
    };
    riskLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    policyViolations?: number;
    organization?: {
        name: string;
    };
}

export interface ProjectsFilter {
    organizationId?: string;
    search?: string;
    riskLevel?: string;
    page?: number;
    pageSize?: number;
    sortBy?: 'name' | 'createdAt' | 'riskLevel';
    sortOrder?: 'asc' | 'desc';
}

export function useProjects(filters?: ProjectsFilter) {
    return useQuery<{ data: Project[]; total: number }>({
        queryKey: ['projects', filters],
        queryFn: () => {
            const params = new URLSearchParams();
            if (filters?.organizationId) params.set('organizationId', filters.organizationId);
            // Server-side search
            if (filters?.search) params.set('search', filters.search);
            // Server-side risk level filter
            if (filters?.riskLevel) params.set('riskLevel', filters.riskLevel);
            // Server-side pagination
            const page = filters?.page || 1;
            const pageSize = filters?.pageSize || 25;
            params.set('limit', String(pageSize));
            params.set('offset', String((page - 1) * pageSize));
            // Server-side sorting
            if (filters?.sortBy) {
                params.set('sortBy', filters.sortBy);
                params.set('sortOrder', filters?.sortOrder || 'desc');
            }
            return authFetch(`${API_BASE}/projects?${params.toString()}`);
        },
    });
}

export function useProject(id: string) {
    return useQuery<Project>({
        queryKey: ['project', id],
        queryFn: () => authFetch(`${API_BASE}/projects/${id}`),
        enabled: !!id,
    });
}

export function useProjectScans(projectId: string) {
    return useQuery<{ results: Scan[]; total: number }>({
        queryKey: ['project-scans', projectId],
        queryFn: () => authFetch(`${API_BASE}/scans?projectId=${projectId}&limit=20`),
        enabled: !!projectId,
    });
}

export function useProjectVulnerabilityTrend(projectId: string, days = 30) {
    return useQuery<{ date: string; critical: number; high: number; medium: number; low: number }[]>({
        queryKey: ['project-vuln-trend', projectId, days],
        queryFn: () => authFetch(`${API_BASE}/projects/${projectId}/vulnerability-trend?days=${days}`),
        enabled: !!projectId,
    });
}

export function useCreateProject() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ organizationId, ...data }: { organizationId: string; name: string; slug?: string; description?: string }) =>
            authFetch(`${API_BASE}/projects?organizationId=${organizationId}`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['projects'] });
        },
    });
}

export function useUpdateProject() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: string; name?: string; description?: string; organizationId?: string }) =>
            authFetch(`${API_BASE}/projects/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['projects'] });
        },
    });
}

export function useDeleteProject() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/projects/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['projects'] });
        },
    });
}

// ============ Organizations API ============

export interface Organization {
    id: string;
    name: string;
    slug: string;
    description?: string;
    createdAt: string;
    updatedAt: string;
    _count?: {
        users: number;
        projects: number;
    };
}

export function useOrganizations() {
    return useQuery<Organization[]>({
        queryKey: ['organizations'],
        queryFn: () => authFetch(`${API_BASE}/organizations`),
    });
}

export function useOrganization(id: string) {
    return useQuery<Organization>({
        queryKey: ['organization', id],
        queryFn: () => authFetch(`${API_BASE}/organizations/${id}`),
        enabled: !!id,
    });
}

export function useCreateOrganization() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: { name: string; slug?: string; description?: string }) =>
            authFetch(`${API_BASE}/organizations`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['organizations'] });
        },
    });
}

export function useUpdateOrganization() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: string; name?: string; description?: string }) =>
            authFetch(`${API_BASE}/organizations/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['organizations'] });
        },
    });
}

export function useDeleteOrganization() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/organizations/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['organizations'] });
        },
    });
}

// ============ Users API ============

export interface User {
    id: string;
    email: string;
    name: string;
    role: 'SYSTEM_ADMIN' | 'ORG_ADMIN' | 'SECURITY_ADMIN' | 'PROJECT_ADMIN' | 'DEVELOPER' | 'VIEWER';
    roleScope?: 'GLOBAL' | 'SYSTEM' | 'ORGANIZATION' | 'PROJECT' | null;
    roleScopeId?: string | null;
    roles?: Array<{
        id: string;
        role: User['role'];
        scope: 'GLOBAL' | 'SYSTEM' | 'ORGANIZATION' | 'PROJECT';
        scopeId?: string | null;
        createdAt?: string;
    }>;
    status: 'ACTIVE' | 'INACTIVE' | 'PENDING';
    mfaEnabled: boolean;
    organizationId?: string;
    organization?: { id?: string; name: string };
    createdAt: string;
    lastLoginAt?: string;
}

export interface UsersFilter {
    organizationId?: string;
    search?: string;
    role?: string;
    status?: string;
    page?: number;
    pageSize?: number;
}

export function useUsers(filters?: UsersFilter) {
    return useQuery<{ data: User[]; total: number }>({
        queryKey: ['users', filters],
        queryFn: () => {
            const params = new URLSearchParams();
            if (filters?.organizationId) params.set('organizationId', filters.organizationId);
            // Server-side search
            if (filters?.search) params.set('search', filters.search);
            // Server-side role filter
            if (filters?.role) params.set('role', filters.role);
            // Server-side status filter
            if (filters?.status) params.set('status', filters.status);
            // Server-side pagination
            const page = filters?.page || 1;
            const pageSize = filters?.pageSize || 25;
            params.set('limit', String(pageSize));
            params.set('offset', String((page - 1) * pageSize));
            return authFetch(`${API_BASE}/users?${params.toString()}`);
        },
    });
}

export function useUser(id: string) {
    return useQuery<User>({
        queryKey: ['user', id],
        queryFn: () => authFetch(`${API_BASE}/users/${id}`),
        enabled: !!id,
    });
}

export function useCreateUser() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: { email: string; name: string; password: string; role?: string; status?: string; organizationId?: string }) =>
            authFetch(`${API_BASE}/users`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
        },
    });
}

export function useUpdateUser() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: string; name?: string; role?: string; status?: string; organizationId?: string }) =>
            authFetch(`${API_BASE}/users/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
        },
    });
}

export function useUpdateUserPassword() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, newPassword }: { id: string; newPassword: string }) =>
            authFetch(`${API_BASE}/users/${id}/password`, {
                method: 'PUT',
                body: JSON.stringify({ newPassword }),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
        },
    });
}

export function useDeleteUser() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/users/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
        },
    });
}

// ============ Exceptions API ============

export interface Exception {
    id: string;
    policyId: string;
    vulnerabilityId: string;
    vulnerability?: {
        cveId: string;
        severity: string;
    };
    projectId?: string;
    project?: { name: string };
    requestedBy: string;
    requestedById: string;
    requestedAt: string;
    reason: string;
    status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
    expiresAt: string;
    approvedBy?: string;
    approvedById?: string;
    approvedAt?: string;
    rejectedBy?: string;
    rejectedAt?: string;
    rejectReason?: string;
}

export function useExceptions(status?: string) {
    return useQuery<Exception[]>({
        queryKey: ['exceptions', status],
        queryFn: () => {
            const params = new URLSearchParams();
            if (status && status !== 'all') params.set('status', status);
            return authFetch(`${API_BASE}/exceptions?${params.toString()}`);
        },
    });
}

export function useMyExceptions() {
    return useQuery<Exception[]>({
        queryKey: ['my-exceptions'],
        queryFn: () => authFetch(`${API_BASE}/exceptions/my`),
    });
}

export function useCreateException() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: {
            cveId?: string;
            scanVulnerabilityId?: string;
            reason: string;
            expiresAt?: string;
            exceptionType?: string;
        }) =>
            authFetch(`${API_BASE}/exceptions`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['exceptions'] });
            queryClient.invalidateQueries({ queryKey: ['my-exceptions'] });
        },
    });
}

export function useApproveException() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/exceptions/${id}/approve`, { method: 'PUT' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['exceptions'] });
        },
    });
}

export function useRejectException() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, reason }: { id: string; reason?: string }) =>
            authFetch(`${API_BASE}/exceptions/${id}/reject`, {
                method: 'PUT',
                body: JSON.stringify({ reason }),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['exceptions'] });
        },
    });
}

// ============ API Tokens API ============

export interface ApiToken {
    id: string;
    name: string;
    tokenPrefix: string;
    permissions: string[];
    expiresAt: string | null;
    lastUsedAt: string | null;
    createdAt: string;
}

export interface CreateApiTokenDto {
    name: string;
    permissions: string[];
    expiresIn?: number; // days
}

export function useApiTokens() {
    return useQuery<ApiToken[]>({
        queryKey: ['api-tokens'],
        queryFn: () => authFetch(`${API_BASE}/api-tokens`),
    });
}

export function useApiToken(id: string) {
    return useQuery<ApiToken>({
        queryKey: ['api-token', id],
        queryFn: () => authFetch(`${API_BASE}/api-tokens/${id}`),
        enabled: !!id,
    });
}

export function useCreateApiToken() {
    const queryClient = useQueryClient();
    return useMutation<{ token: string; tokenInfo: ApiToken }, Error, CreateApiTokenDto>({
        mutationFn: (data: CreateApiTokenDto) =>
            authFetch(`${API_BASE}/api-tokens`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
        },
    });
}

export function useDeleteApiToken() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/api-tokens/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
        },
    });
}

// ============ Notification Channels API ============

export interface NotificationRule {
    id: string;
    channelId: string;
    eventType: string;
    conditions?: Record<string, unknown>;
    isActive: boolean;
    createdAt: string;
    updatedAt: string;
}

export interface NotificationChannel {
    id: string;
    name: string;
    type: 'MATTERMOST' | 'EMAIL' | 'WEBHOOK';
    config: Record<string, unknown>;
    isActive: boolean;
    rules?: NotificationRule[];
    createdAt: string;
    updatedAt: string;
}

export function useNotificationChannels() {
    return useQuery<NotificationChannel[]>({
        queryKey: ['notification-channels'],
        queryFn: () => authFetch(`${API_BASE}/notification-channels`),
    });
}

export function useNotificationChannel(id: string) {
    return useQuery<NotificationChannel>({
        queryKey: ['notification-channel', id],
        queryFn: () => authFetch(`${API_BASE}/notification-channels/${id}`),
        enabled: !!id,
    });
}

export function useCreateNotificationChannel() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: {
            name: string;
            type: 'MATTERMOST' | 'EMAIL' | 'WEBHOOK';
            config: Record<string, unknown>;
            isActive?: boolean;
        }) =>
            authFetch(`${API_BASE}/notification-channels`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

export function useUpdateNotificationChannel() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: {
            id: string;
            name?: string;
            config?: Record<string, unknown>;
            isActive?: boolean;
        }) =>
            authFetch(`${API_BASE}/notification-channels/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

export function useDeleteNotificationChannel() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/notification-channels/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

export function useTestNotificationChannel() {
    return useMutation<{ success: boolean; message: string }, Error, string>({
        mutationFn: (channelId: string) =>
            authFetch(`${API_BASE}/notification-channels/${channelId}/test`, {
                method: 'POST',
            }),
    });
}

export function useAddNotificationRule() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ channelId, ...data }: {
            channelId: string;
            eventType: string;
            conditions?: Record<string, unknown>;
            isActive?: boolean;
        }) =>
            authFetch(`${API_BASE}/notification-channels/${channelId}/rules`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

export function useUpdateNotificationRule() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ channelId, ruleId, ...data }: {
            channelId: string;
            ruleId: string;
            eventType?: string;
            conditions?: Record<string, unknown>;
            isActive?: boolean;
        }) =>
            authFetch(`${API_BASE}/notification-channels/${channelId}/rules/${ruleId}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

export function useDeleteNotificationRule() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ channelId, ruleId }: { channelId: string; ruleId: string }) =>
            authFetch(`${API_BASE}/notification-channels/${channelId}/rules/${ruleId}`, {
                method: 'DELETE',
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

// Notification Channel Statistics
export interface NotificationChannelStats {
    total: number;
    active: number;
    inactive: number;
    totalRules: number;
    byType: Record<string, number>;
    recentNotifications: number;
}

export function useNotificationChannelStats() {
    const { data: channels } = useNotificationChannels();
    
    const stats: NotificationChannelStats = {
        total: channels?.length || 0,
        active: channels?.filter(c => c.isActive).length || 0,
        inactive: channels?.filter(c => !c.isActive).length || 0,
        totalRules: channels?.reduce((sum, c) => sum + (c.rules?.length || 0), 0) || 0,
        byType: channels?.reduce((acc, c) => {
            acc[c.type] = (acc[c.type] || 0) + 1;
            return acc;
        }, {} as Record<string, number>) || {},
        recentNotifications: 0,
    };
    
    return { data: stats };
}

// Clone Notification Channel
export function useCloneNotificationChannel() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ channelId, newName }: { channelId: string; newName: string }) => {
            const channel = await authFetch(`${API_BASE}/notification-channels/${channelId}`);
            return authFetch(`${API_BASE}/notification-channels`, {
                method: 'POST',
                body: JSON.stringify({
                    name: newName,
                    type: channel.type,
                    config: channel.config,
                    isActive: false,
                }),
            });
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

// Bulk update channel status
export function useBulkUpdateChannelStatus() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async ({ channelIds, isActive }: { channelIds: string[]; isActive: boolean }) => {
            const results = await Promise.all(
                channelIds.map(id =>
                    authFetch(`${API_BASE}/notification-channels/${id}`, {
                        method: 'PUT',
                        body: JSON.stringify({ isActive }),
                    })
                )
            );
            return results;
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
        },
    });
}

// ============ Stats API ============

export interface StatsOverview {
    total: number;
    bySeverity: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        unknown: number;
    };
    byStatus: {
        open: number;
        inProgress: number;
        fixed: number;
        ignored: number;
    };
    recentCritical: Array<{
        id: string;
        cveId: string;
        title: string;
        pkgName: string;
        project: string;
        createdAt: string;
    }>;
}

export interface ProjectStats {
    id: string;
    name: string;
    slug: string;
    organization?: string;
    totalScans: number;
    lastScan?: {
        id: string;
        scannedAt: string;
        summary?: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            totalVulns: number;
        };
    };
}

export interface TrendData {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export function useStatsOverview(organizationId?: string) {
    return useQuery<StatsOverview>({
        queryKey: ['stats-overview', organizationId],
        queryFn: () => {
            const params = new URLSearchParams();
            if (organizationId) params.set('organizationId', organizationId);
            return authFetch(`${API_BASE}/stats/overview?${params.toString()}`);
        },
    });
}

export function useStatsByProject(organizationId?: string) {
    return useQuery<ProjectStats[]>({
        queryKey: ['stats-by-project', organizationId],
        queryFn: () => {
            const params = new URLSearchParams();
            if (organizationId) params.set('organizationId', organizationId);
            return authFetch(`${API_BASE}/stats/by-project?${params.toString()}`);
        },
    });
}

export function useStatsTrend(organizationId?: string, days = 7) {
    return useQuery<TrendData[]>({
        queryKey: ['stats-trend', organizationId, days],
        queryFn: () => {
            const params = new URLSearchParams();
            if (organizationId) params.set('organizationId', organizationId);
            params.set('days', days.toString());
            return authFetch(`${API_BASE}/stats/trend?${params.toString()}`);
        },
    });
}

// ============ Notifications API ============

export interface Notification {
    id: string;
    type: 'critical_vuln' | 'high_vuln' | 'policy_violation' | 'exception' | 'scan_complete' | 'system';
    title: string;
    message: string;
    isRead: boolean;
    createdAt: string;
    link?: string;
}

export function useNotifications() {
    return useQuery<Notification[]>({
        queryKey: ['notifications'],
        queryFn: () => authFetch(`${API_BASE}/notifications`),
        refetchInterval: 3000,
        refetchOnMount: 'always',
        refetchOnWindowFocus: true,
        staleTime: 0,
    });
}

export function useMarkNotificationRead() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/notifications/${id}/read`, { method: 'POST' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
        },
    });
}

export function useMarkAllNotificationsRead() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: () =>
            authFetch(`${API_BASE}/notifications/read-all`, { method: 'POST' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
        },
    });
}

export function useDeleteNotification() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/notifications/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
        },
    });
}

export function useDeleteNotifications() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (ids: string[]) =>
            authFetch(`${API_BASE}/notifications/delete-bulk`, {
                method: 'POST',
                body: JSON.stringify({ ids }),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
        },
    });
}

// ============ Login History / Audit Logs API ============

export interface LoginHistoryEntry {
    id: string;
    userId: string;
    user?: { name: string; email: string };
    ipAddress: string;
    userAgent: string;
    success: boolean;
    failureReason?: string;
    createdAt: string;
}

export function useLoginHistory(limit = 50) {
    return useQuery<LoginHistoryEntry[]>({
        queryKey: ['login-history', limit],
        queryFn: () => authFetch(`${API_BASE}/auth/login-history?limit=${limit}`),
    });
}

// ============ Audit Logs API ============

export interface AuditLog {
    id: string;
    userId?: string;
    user?: { id: string; name: string; email: string };
    organizationId?: string;
    organization?: { id: string; name: string };
    action: string;
    resource: string;
    resourceId?: string;
    details?: Record<string, unknown>;
    ipAddress?: string;
    userAgent?: string;
    createdAt: string;
}

export interface AuditLogFilters {
    action?: string;
    resource?: string;
    userId?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
    offset?: number;
}

export interface AuditLogStats {
    total: number;
    byAction: Record<string, number>;
    byResource: Record<string, number>;
    trend: { date: string; count: number }[];
}

export function useAuditLogs(filters?: AuditLogFilters) {
    return useQuery<{ results: AuditLog[]; total: number }>({
        queryKey: ['audit-logs', filters],
        queryFn: () => {
            const params = new URLSearchParams();
            if (filters?.action) params.set('action', filters.action);
            if (filters?.resource) params.set('resource', filters.resource);
            if (filters?.userId) params.set('userId', filters.userId);
            if (filters?.startDate) params.set('startDate', filters.startDate);
            if (filters?.endDate) params.set('endDate', filters.endDate);
            if (filters?.limit) params.set('limit', filters.limit.toString());
            if (filters?.offset) params.set('offset', filters.offset.toString());
            return authFetch(`${API_BASE}/audit-logs?${params.toString()}`);
        },
    });
}

export function useAuditLogActions() {
    return useQuery<{ id: string; label: string }[]>({
        queryKey: ['audit-log-actions'],
        queryFn: () => authFetch(`${API_BASE}/audit-logs/actions`),
    });
}

export function useAuditLogResources() {
    return useQuery<{ id: string; label: string }[]>({
        queryKey: ['audit-log-resources'],
        queryFn: () => authFetch(`${API_BASE}/audit-logs/resources`),
    });
}

export function useAuditLogStats(days = 7) {
    return useQuery<AuditLogStats>({
        queryKey: ['audit-log-stats', days],
        queryFn: () => authFetch(`${API_BASE}/audit-logs/stats?days=${days}`),
    });
}

// ============ Reports API ============

export interface Report {
    id: string;
    name: string;
    type: 'vulnerability_summary' | 'trend_analysis' | 'compliance_audit' | 'project_status';
    status: 'pending' | 'generating' | 'completed' | 'failed';
    format: 'pdf' | 'csv' | 'json';
    createdAt: string;
    completedAt?: string;
    downloadUrl?: string;
}

export interface ReportFilters {
    type?: string;
    status?: string;
    format?: string;
    search?: string;
    dateFrom?: string;
    dateTo?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface ReportStatistics {
    total: number;
    statusCounts: {
        completed: number;
        generating: number;
        pending: number;
        failed: number;
    };
    completionRate: number;
    typeDistribution: Array<{
        type: string;
        name: string;
        count: number;
    }>;
    dailyTrend: Array<{
        date: string;
        count: number;
    }>;
    avgGenerationTime: number;
    recentCount: number;
}

export function useReports(filters?: ReportFilters) {
    return useQuery<{ data: Report[]; pagination: { page: number; limit: number; total: number; totalPages: number } }>({
        queryKey: ['reports', filters],
        queryFn: () => {
            const params = new URLSearchParams();
            if (filters?.type) params.set('type', filters.type);
            if (filters?.status) params.set('status', filters.status);
            if (filters?.format) params.set('format', filters.format);
            if (filters?.search) params.set('search', filters.search);
            if (filters?.dateFrom) params.set('dateFrom', filters.dateFrom);
            if (filters?.dateTo) params.set('dateTo', filters.dateTo);
            if (filters?.page) params.set('page', String(filters.page));
            if (filters?.limit) params.set('limit', String(filters.limit));
            if (filters?.sortBy) params.set('sortBy', filters.sortBy);
            if (filters?.sortOrder) params.set('sortOrder', filters.sortOrder);
            
            const queryString = params.toString();
            return authFetch(`${API_BASE}/reports${queryString ? `?${queryString}` : ''}`);
        },
        // Auto-refresh every 5 seconds to catch status updates
        refetchInterval: 5000,
    });
}

export function useReportStatistics() {
    return useQuery<ReportStatistics>({
        queryKey: ['report-statistics'],
        queryFn: () => authFetch(`${API_BASE}/reports/statistics`),
        refetchInterval: 10000, // Refresh every 10 seconds
    });
}

export function useReport(id: string) {
    return useQuery<Report>({
        queryKey: ['report', id],
        queryFn: () => authFetch(`${API_BASE}/reports/${id}`),
        enabled: !!id,
    });
}

export function useReportPreview(id: string) {
    return useQuery<Record<string, any>>({
        queryKey: ['report-preview', id],
        queryFn: () => authFetch(`${API_BASE}/reports/${id}/download`).then(res => res),
        enabled: !!id,
        staleTime: 60000, // Don't refetch for 1 minute
    });
}

export function useCreateReport() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: { name: string; type: string; format: string; parameters?: Record<string, unknown> }) =>
            authFetch(`${API_BASE}/reports`, {
                method: 'POST',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['reports'] });
        },
    });
}

export function useDeleteReport() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) =>
            authFetch(`${API_BASE}/reports/${id}`, { method: 'DELETE' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['reports'] });
        },
    });
}

export function useUpdateReport() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: string; name?: string; format?: string }) =>
            authFetch(`${API_BASE}/reports/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['reports'] });
        },
    });
}

// ============ Compliance API ============

export interface ComplianceReport {
    id: string;
    organizationId: string;
    reportType: 'PCI-DSS' | 'SOC2' | 'HIPAA' | 'ISO27001' | 'GENERAL';
    generatedAt: string;
    summary: {
        totalVulnerabilities: number;
        criticalUnresolved: number;
        highUnresolved: number;
        meanTimeToResolve: number;
        complianceScore: number;
    };
    sections: {
        title: string;
        status: 'PASS' | 'FAIL' | 'WARNING' | 'NOT_APPLICABLE';
        findings: string[];
        recommendations: string[];
    }[];
}

export interface ViolationHistory {
    total: number;
    byPolicy: { policyName: string; count: number }[];
    bySeverity: Record<string, number>;
    trend: { date: string; count: number }[];
}

export function useComplianceReport(reportType?: string) {
    return useQuery<ComplianceReport>({
        queryKey: ['compliance-report', reportType],
        queryFn: () => {
            const params = new URLSearchParams();
            if (reportType) params.set('reportType', reportType);
            return authFetch(`${API_BASE}/compliance/report?${params.toString()}`);
        },
    });
}

export function useViolationHistory(days = 30) {
    return useQuery<ViolationHistory>({
        queryKey: ['violation-history', days],
        queryFn: () => authFetch(`${API_BASE}/compliance/violations?days=${days}`),
    });
}

// ============ Settings API ============

export function useSettings<T = unknown>(key: string) {
    return useQuery<T>({
        queryKey: ['settings', key],
        queryFn: () => authFetch(`${API_BASE}/settings/${key}`),
    });
}

export function useAllSettings() {
    return useQuery<Record<string, unknown>>({
        queryKey: ['settings'],
        queryFn: () => authFetch(`${API_BASE}/settings`),
    });
}

export function useUpdateSettings() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ key, value }: { key: string; value: unknown }) =>
            authFetch(`${API_BASE}/settings/${key}`, {
                method: 'PUT',
                body: JSON.stringify({ value }),
            }),
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: ['settings', variables.key] });
            queryClient.invalidateQueries({ queryKey: ['settings'] });
        },
    });
}

export type ClustaraAuthType = 'NONE' | 'X_API_KEY' | 'BEARER';
export type ClustaraDeliveryType = 'TRIVY' | 'SBOM';
export type ClustaraDeliveryStatus = 'PENDING' | 'SENDING' | 'SUCCESS' | 'FAILED';

export interface ClustaraSettings {
    enabled: boolean;
    autoSend: boolean;
    baseUrl: string;
    scanPath: string;
    sbomPath: string;
    authType: ClustaraAuthType;
    credential?: string;
    credentialConfigured: boolean;
    defaultClusterId: string;
    scanner: string;
    generator: string;
    timeoutSeconds: number;
    maxAttempts: number;
    verifyTls: boolean;
}

export interface ClustaraDelivery {
    id: string;
    scanResultId: string;
    type: ClustaraDeliveryType;
    status: ClustaraDeliveryStatus;
    clusterId: string;
    scanner?: string | null;
    generator?: string | null;
    imageDigest: string;
    attempts: number;
    maxAttempts: number;
    httpStatus?: number | null;
    responseSummary?: string | null;
    lastError?: string | null;
    nextAttemptAt: string;
    succeededAt?: string | null;
    createdAt: string;
    scanResult?: { id: string; imageRef: string; artifactName?: string | null; projectId: string };
}

export function useClustaraSettings() {
    return useQuery<ClustaraSettings>({
        queryKey: ['clustara-settings'],
        queryFn: () => authFetch(`${API_BASE}/clustara/settings`),
    });
}

export function useClustaraOptions() {
    return useQuery<{ enabled: boolean; defaultClusterId: string; scanner: string; generator: string }>({
        queryKey: ['clustara-options'],
        queryFn: () => authFetch(`${API_BASE}/clustara/options`),
    });
}

export function useUpdateClustaraSettings() {
    const queryClient = useQueryClient();
    return useMutation<ClustaraSettings, Error, Partial<ClustaraSettings>>({
        mutationFn: (settings) => authFetch(`${API_BASE}/clustara/settings`, {
            method: 'PUT',
            body: JSON.stringify(settings),
        }),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['clustara-settings'] }),
    });
}

export function useTestClustaraConnection() {
    return useMutation<{ success: boolean; status: number; durationMs: number; message: string }, Error, Partial<ClustaraSettings>>({
        mutationFn: (settings) => authFetch(`${API_BASE}/clustara/test`, {
            method: 'POST',
            body: JSON.stringify(settings),
        }),
    });
}

export function useClustaraDeliveries(limit = 50) {
    return useQuery<ClustaraDelivery[]>({
        queryKey: ['clustara-deliveries', limit],
        queryFn: () => authFetch(`${API_BASE}/clustara/deliveries?limit=${limit}`),
        refetchInterval: 10000,
    });
}

export function useScanClustaraDeliveries(scanId?: string) {
    return useQuery<ClustaraDelivery[]>({
        queryKey: ['clustara-scan-deliveries', scanId],
        queryFn: () => authFetch(`${API_BASE}/clustara/scans/${scanId}/deliveries`),
        enabled: Boolean(scanId),
        refetchInterval: 10000,
    });
}

export function useQueueClustaraDelivery(scanId: string) {
    const queryClient = useQueryClient();
    return useMutation<ClustaraDelivery, Error, {
        type: ClustaraDeliveryType;
        clusterId: string;
        imageDigest?: string;
        imageRef?: string;
        scanner?: string;
        generator?: string;
    }>({
        mutationFn: (input) => authFetch(`${API_BASE}/clustara/scans/${scanId}/deliveries`, {
            method: 'POST',
            body: JSON.stringify(input),
        }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['clustara-scan-deliveries', scanId] });
            queryClient.invalidateQueries({ queryKey: ['clustara-deliveries'] });
        },
    });
}

export function useRetryClustaraDelivery(scanId?: string) {
    const queryClient = useQueryClient();
    return useMutation<ClustaraDelivery, Error, string>({
        mutationFn: (id) => authFetch(`${API_BASE}/clustara/deliveries/${id}/retry`, { method: 'POST' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['clustara-deliveries'] });
            if (scanId) queryClient.invalidateQueries({ queryKey: ['clustara-scan-deliveries', scanId] });
        },
    });
}

// Typed hooks for specific settings
export interface WorkflowSettings {
    states: Array<{
        id: string;
        name: string;
        color: string;
        description: string;
    }>;
    transitions: Array<{
        from: string;
        to: string;
        requiredRole: string;
    }>;
}

export interface TrivySettings {
    outputFormat: 'json' | 'table' | 'sarif';
    schemaVersion: number;
    severities: string[];
    ignoreUnfixed: boolean;
    timeout: string;
    cacheDir: string;
    scanners: string[];
}

export function useZapScan() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (request: ZapScanRequest) => {
            const token = useAuthStore.getState().accessToken;
            const params = request.projectId ? `?projectId=${encodeURIComponent(request.projectId)}` : '';
            const response = await fetch(`${API_BASE}/scans/scan/zap${params}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
                body: JSON.stringify({
                    targetUrl: request.targetUrl,
                    scanMode: request.scanMode,
                    confirmActiveScan: request.confirmActiveScan,
                    authentication: request.authentication,
                    projectName: request.projectName,
                    organizationId: request.organizationId,
                    imageRef: request.imageRef,
                    tag: request.tag,
                    scanOperationId: request.scanOperationId,
                    targetProfileId: request.targetProfileId,
                }),
            });

            if (!response.ok) {
                const responseText = await response.text().catch(() => '');
                let message = 'ZAP scan failed';
                if (responseText) {
                    try {
                        const error = JSON.parse(responseText);
                        message = error.message || message;
                    } catch {
                        message = responseText.slice(0, 500) || message;
                    }
                }
                throw new Error(message);
            }

            return response.json();
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['scans'], exact: false });
            queryClient.invalidateQueries({ queryKey: ['project-scans'], exact: false });
            queryClient.invalidateQueries({ queryKey: ['projects'], exact: false });
            queryClient.invalidateQueries({ queryKey: ['notifications'] });
            queryClient.refetchQueries({ queryKey: ['notifications'] });
        },
    });
}

export interface CheckovSettings {
    allowInternalModuleDownload: boolean;
}

export interface ZapSettings {
    enabled: boolean;
    zapBaseUrl: string;
    apiKeyConfigured: boolean;
    apiKey?: string;
    connectTimeoutSeconds: number;
    maxScanDurationMinutes: number;
    maxConcurrentScans: number;
    allowBaselineScan: boolean;
    allowActiveScan: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
    defaultRiskThresholdForNotification: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    targetProfiles: ZapTargetProfile[];
}

export interface ZapTargetProfile {
    id: string;
    name: string;
    enabled: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
    maxScanDurationMinutes: number;
    defaultRiskThresholdForNotification: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
}

export interface AiSettings {
    provider: 'openai' | 'anthropic' | 'vllm' | 'ollama' | 'custom';
    apiUrl?: string;
    apiKey?: string;
    summaryModel: string;
    remediationModel: string;
    maxTokens: number;
    temperature: number;
    timeout: number;  // Request timeout in seconds (default: 60)
    allowMockFallback?: boolean;
    enableAutoSummary: boolean;
    enableRemediationGuide: boolean;
}


export function useWorkflowSettings() {
    return useSettings<WorkflowSettings>('workflows');
}

export function useTrivySettings() {
    return useSettings<TrivySettings>('trivy');
}

export function useCheckovSettings() {
    return useSettings<CheckovSettings>('checkov');
}

export function useZapSettings() {
    return useSettings<ZapSettings>('zap');
}

export function useZapConnectionTest() {
    return useMutation<{ connected: true; version: string }, Error>({
        mutationFn: () => authFetch(`${API_BASE}/scans/zap/test-connection`, { method: 'POST' }),
    });
}

export function useAiSettings() {
    return useSettings<AiSettings>('ai');
}

// ============ Profile API ============

export interface UserProfile {
    id: string;
    name: string;
    email: string;
    role: string;
    status: string;
    mfaEnabled: boolean;
    organization?: { id: string; name: string };
    createdAt: string;
}

export interface NotificationSettings {
    emailAlerts: boolean;
    criticalOnly: boolean;
    weeklyDigest: boolean;
    scanComplete: boolean;
    criticalVulns: boolean;
    highVulns: boolean;
    policyViolations: boolean;
    exceptionAlerts: boolean;
}

export function useProfile() {
    return useQuery<UserProfile>({
        queryKey: ['profile'],
        queryFn: () => authFetch(`${API_BASE}/users/me`),
    });
}

export function useUpdateProfile() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: { name?: string }) =>
            authFetch(`${API_BASE}/users/me`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['profile'] });
        },
    });
}

export function useNotificationSettings() {
    return useQuery<NotificationSettings>({
        queryKey: ['notification-settings'],
        queryFn: () => authFetch(`${API_BASE}/users/me/notification-settings`),
    });
}

export function useUpdateNotificationSettings() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: Partial<NotificationSettings>) =>
            authFetch(`${API_BASE}/users/me/notification-settings`, {
                method: 'PUT',
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notification-settings'] });
        },
    });
}

// ============ Licenses API ============

export type LicenseClassification =
    | 'FORBIDDEN'
    | 'RESTRICTED'
    | 'RECIPROCAL'
    | 'NOTICE'
    | 'PERMISSIVE'
    | 'UNENCUMBERED'
    | 'UNKNOWN';

export interface License {
    id: string;
    spdxId: string;
    name: string;
    classification: LicenseClassification;
    description?: string;
    osiApproved: boolean;
    fsfLibre: boolean;
    url?: string;
    createdAt: string;
    updatedAt: string;
}

export interface LicenseStats {
    total: number;
    byClassification: Record<LicenseClassification, number>;
    uniqueLicenses: number;
    uniquePackages: number;
}

export interface LicenseSummary {
    id: string;
    spdxId: string;
    name: string;
    classification: LicenseClassification;
    packageCount: number;
}

export interface PackageLicense {
    id: string;
    licenseName: string;
    pkgName: string;
    pkgVersion: string;
    pkgPath?: string;
    confidence: number;
    createdAt: string;
}

export function useLicenses(params?: { classification?: LicenseClassification; search?: string }) {
    return useQuery<License[]>({
        queryKey: ['licenses', params],
        queryFn: () => {
            const searchParams = new URLSearchParams();
            if (params?.classification) searchParams.set('classification', params.classification);
            if (params?.search) searchParams.set('search', params.search);
            const queryString = searchParams.toString();
            return authFetch(`${API_BASE}/licenses${queryString ? `?${queryString}` : ''}`);
        },
    });
}

export function useLicenseStats(projectId?: string) {
    return useQuery<LicenseStats>({
        queryKey: ['license-stats', projectId],
        queryFn: () => {
            const url = projectId
                ? `${API_BASE}/licenses/stats?projectId=${projectId}`
                : `${API_BASE}/licenses/stats`;
            return authFetch(url);
        },
    });
}

export function useLicensesByProject(projectId: string) {
    return useQuery<LicenseSummary[]>({
        queryKey: ['licenses-by-project', projectId],
        queryFn: () => authFetch(`${API_BASE}/licenses/by-project/${projectId}`),
        enabled: !!projectId,
    });
}

export function useLicensesByScan(scanId: string) {
    return useQuery<LicenseSummary[]>({
        queryKey: ['licenses-by-scan', scanId],
        queryFn: () => authFetch(`${API_BASE}/licenses/by-scan/${scanId}`),
        enabled: !!scanId,
    });
}

export function usePackagesByLicense(scanId: string, licenseName: string) {
    return useQuery<PackageLicense[]>({
        queryKey: ['packages-by-license', scanId, licenseName],
        queryFn: () =>
            authFetch(
                `${API_BASE}/licenses/by-scan/${scanId}/packages?licenseName=${encodeURIComponent(licenseName)}`
            ),
        enabled: !!scanId && !!licenseName,
    });
}

export function useSeedLicenses() {
    const queryClient = useQueryClient();
    return useMutation<{ seeded: number }>({
        mutationFn: () => authFetch(`${API_BASE}/licenses/seed`, { method: 'POST' }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['licenses'] });
            queryClient.invalidateQueries({ queryKey: ['license-stats'] });
        },
    });
}

export function useUpdateLicense() {
    const queryClient = useQueryClient();
    return useMutation<
        License,
        Error,
        {
            id: string;
            data: Partial<Omit<Pick<License, 'classification' | 'description' | 'url' | 'osiApproved' | 'fsfLibre'>, 'description' | 'url'>> & {
                description?: string | null;
                url?: string | null;
            };
        }
    >({
        mutationFn: ({ id, data }) =>
            authFetch(`${API_BASE}/licenses/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['licenses'] });
            queryClient.invalidateQueries({ queryKey: ['license-stats'] });
            queryClient.invalidateQueries({ queryKey: ['tracked-licenses'] });
            queryClient.invalidateQueries({ queryKey: ['project-license-summary'] });
        },
    });
}

// Tracked license with project/scan info
export interface TrackedLicenseInfo {
    id: string;
    licenseName: string;
    pkgName: string;
    pkgVersion: string;
    pkgPath?: string;
    classification: LicenseClassification;
    spdxId?: string;
    scanId: string;
    scanCreatedAt: string;
    imageRef?: string;
    artifactName?: string;
    projectId: string;
    projectName: string;
    organizationName?: string;
}

export interface ProjectLicenseSummary {
    projectId: string;
    projectName: string;
    organizationName?: string;
    lastScanAt?: string;
    licenseStats: {
        total: number;
        forbidden: number;
        restricted: number;
        unknown: number;
    };
}

export function useTrackedLicenses(params?: {
    projectId?: string;
    classification?: LicenseClassification;
    search?: string;
    limit?: number;
    offset?: number;
}) {
    return useQuery<{ data: TrackedLicenseInfo[]; total: number }>({
        queryKey: ['tracked-licenses', params],
        queryFn: () => {
            const searchParams = new URLSearchParams();
            if (params?.projectId) searchParams.set('projectId', params.projectId);
            if (params?.classification) searchParams.set('classification', params.classification);
            if (params?.search) searchParams.set('search', params.search);
            if (params?.limit) searchParams.set('limit', params.limit.toString());
            if (params?.offset) searchParams.set('offset', params.offset.toString());
            const queryString = searchParams.toString();
            return authFetch(`${API_BASE}/licenses/tracked${queryString ? `?${queryString}` : ''}`);
        },
    });
}

export function useProjectLicenseSummary(params?: {
    limit?: number;
    offset?: number;
    search?: string;
}) {
    return useQuery<{ data: ProjectLicenseSummary[]; total: number }>({
        queryKey: ['project-license-summary', params],
        queryFn: () => {
            const searchParams = new URLSearchParams();
            if (params?.limit) searchParams.set('limit', params.limit.toString());
            if (params?.offset) searchParams.set('offset', params.offset.toString());
            if (params?.search) searchParams.set('search', params.search);
            const queryString = searchParams.toString();
            return authFetch(`${API_BASE}/licenses/by-project-summary${queryString ? `?${queryString}` : ''}`);
        },
    });
}

// ============================================
// Compliance & Remediation (offline, bundled mappings)
// ============================================

export interface OwaspCategorySummary {
    id: string;
    name: string;
    count: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    cweIds: string[];
    sampleCveIds: string[];
}

export interface CweTop25Summary {
    rank: number;
    cweId: string;
    name: string;
    count: number;
}

export interface OwaspComplianceReport {
    projectId: string;
    generatedAt: string;
    totalOpenVulnerabilities: number;
    owaspTop10: OwaspCategorySummary[];
    cweTop25: CweTop25Summary[];
    unmappedCount: number;
}

export function useOwaspComplianceReport(projectId?: string) {
    return useQuery<OwaspComplianceReport>({
        queryKey: ['owasp-compliance-report', projectId],
        queryFn: () => authFetch(`${API_BASE}/reports/compliance?projectId=${projectId}`),
        enabled: !!projectId,
    });
}

export interface RemediationGuidance {
    cweId: string;
    guidance: string;
}

export function useRemediationGuidance(cweIds?: string[]) {
    const key = (cweIds || []).join(',');
    return useQuery<RemediationGuidance[]>({
        queryKey: ['remediation-guidance', key],
        queryFn: () => authFetch(`${API_BASE}/reports/remediation?cweIds=${encodeURIComponent(key)}`),
        enabled: key.length > 0,
    });
}

// ============================================
// Custom Semgrep Rules (CxQL-style customization)
// ============================================

export interface SemgrepRule {
    id: string;
    name: string;
    description?: string | null;
    yaml: string;
    isActive: boolean;
    createdBy?: { id: string; name: string; email: string } | null;
    createdAt: string;
    updatedAt: string;
}

export interface SemgrepRuleInput {
    name: string;
    description?: string;
    yaml: string;
    isActive?: boolean;
}

export function useSemgrepRules() {
    return useQuery<SemgrepRule[]>({
        queryKey: ['semgrep-rules'],
        queryFn: () => authFetch(`${API_BASE}/semgrep-rules`),
    });
}

export function useCreateSemgrepRule() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (input: SemgrepRuleInput) =>
            authFetch(`${API_BASE}/semgrep-rules`, { method: 'POST', body: JSON.stringify(input) }),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['semgrep-rules'] }),
    });
}

export function useUpdateSemgrepRule() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...input }: Partial<SemgrepRuleInput> & { id: string }) =>
            authFetch(`${API_BASE}/semgrep-rules/${id}`, { method: 'PUT', body: JSON.stringify(input) }),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['semgrep-rules'] }),
    });
}

export function useDeleteSemgrepRule() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: string) => authFetch(`${API_BASE}/semgrep-rules/${id}`, { method: 'DELETE' }),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['semgrep-rules'] }),
    });
}

// ============================================
// Best Fix suggestions (Best Fix Location approximation)
// ============================================

export interface PackageBestFix {
    type: 'package';
    pkgName: string;
    currentVersion: string;
    recommendedVersion: string;
    resolves: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    topSeverity: string;
    cveIds: string[];
}

export interface CodeBestFix {
    type: 'code';
    ruleId: string;
    file: string;
    title?: string | null;
    locations: string[];
    resolves: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    topSeverity: string;
}

export interface BestFixesResponse {
    scanResultId: string;
    totalOpenFindings: number;
    packageFixes: PackageBestFix[];
    codeFixes: CodeBestFix[];
}

export function useScanBestFixes(scanId?: string) {
    return useQuery<BestFixesResponse>({
        queryKey: ['scan-best-fixes', scanId],
        queryFn: () => authFetch(`${API_BASE}/scans/${scanId}/best-fixes`),
        enabled: !!scanId,
    });
}
