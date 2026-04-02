'use client';

import { useEffect, useMemo, useState } from 'react';
import { CheckCircle, Info, Loader2, RefreshCw, Save, X } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '@/stores/auth-store';

const API_BASE = '/api';
const roles = ['SYSTEM_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'PROJECT_ADMIN', 'DEVELOPER', 'VIEWER'] as const;

const permissionGroups = [
    { name: '스캔', permissions: [['scan:read', '조회'], ['scan:create', '업로드'], ['scan:delete', '삭제']] },
    { name: '취약점', permissions: [['vuln:read', '조회'], ['vuln:update', '상태 변경'], ['vuln:assign', '담당자 지정']] },
    { name: '프로젝트', permissions: [['project:read', '조회'], ['project:create', '생성'], ['project:update', '수정'], ['project:delete', '삭제']] },
    { name: '정책', permissions: [['policy:read', '조회'], ['policy:create', '생성'], ['policy:update', '수정'], ['policy:delete', '삭제']] },
    { name: '예외', permissions: [['exception:read', '조회'], ['exception:request', '요청'], ['exception:approve', '승인']] },
    { name: '사용자', permissions: [['user:read', '조회'], ['user:create', '생성'], ['user:update', '수정'], ['user:delete', '삭제']] },
    { name: '조직', permissions: [['org:read', '조회'], ['org:create', '생성'], ['org:update', '수정'], ['org:delete', '삭제']] },
    { name: '설정', permissions: [['settings:read', '조회'], ['settings:update', '수정']] },
] as const;

async function authFetch(url: string, options: RequestInit = {}) {
    const token = useAuthStore.getState().accessToken;
    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(options.headers || {}),
        },
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({ message: 'Request failed' }));
        throw new Error(error.message || 'Request failed');
    }
    return response.json();
}

export default function PermissionsPage() {
    const queryClient = useQueryClient();
    const [matrix, setMatrix] = useState<Record<string, string[]>>({});
    const [saved, setSaved] = useState(false);
    const [hasChanges, setHasChanges] = useState(false);

    const { data, isLoading, isError, refetch } = useQuery({
        queryKey: ['settings', 'permissions'],
        queryFn: () => authFetch(`${API_BASE}/settings/permissions`),
    });

    const updateMutation = useMutation({
        mutationFn: (value: Record<string, string[]>) =>
            authFetch(`${API_BASE}/settings/permissions`, {
                method: 'PUT',
                body: JSON.stringify({ value }),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['settings', 'permissions'] });
        },
    });

    useEffect(() => {
        if (data) {
            setMatrix(data);
            setHasChanges(false);
        }
    }, [data]);

    const totalPermissions = useMemo(
        () => permissionGroups.reduce((total, group) => total + group.permissions.length, 0),
        [],
    );

    const togglePermission = (role: string, permission: string) => {
        if (role === 'SYSTEM_ADMIN') return;
        setMatrix((current) => {
            const currentPermissions = current[role] || [];
            const nextPermissions = currentPermissions.includes(permission)
                ? currentPermissions.filter((item) => item !== permission)
                : [...currentPermissions, permission];
            return { ...current, [role]: nextPermissions };
        });
        setHasChanges(true);
    };

    const handleSave = async () => {
        await updateMutation.mutateAsync(matrix);
        setSaved(true);
        setHasChanges(false);
        window.setTimeout(() => setSaved(false), 2500);
    };

    if (isLoading) {
        return <div className="flex items-center justify-center h-64"><Loader2 className="h-8 w-8 animate-spin text-blue-600" /></div>;
    }

    if (isError) {
        return (
            <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-center text-red-700 dark:border-red-900/40 dark:bg-red-950/20 dark:text-red-300">
                <p>권한 설정을 불러오지 못했습니다.</p>
                <button type="button" onClick={() => refetch()} className="mt-4 rounded-xl bg-red-600 px-4 py-2 text-sm font-medium text-white">다시 시도</button>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">권한 관리</h1>
                    <p className="mt-1 text-slate-600 dark:text-slate-400">역할별 실제 API 권한을 여기서 조정할 수 있습니다.</p>
                </div>
                <div className="flex items-center gap-3">
                    {saved && <span className="flex items-center gap-2 text-green-600"><CheckCircle className="h-4 w-4" />저장됨</span>}
                    {hasChanges && <span className="text-sm text-amber-600">변경사항 있음</span>}
                    <button type="button" onClick={() => refetch()} className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"><RefreshCw className="h-4 w-4" /></button>
                    <button type="button" onClick={handleSave} disabled={!hasChanges || updateMutation.isPending} className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50">
                        {updateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}저장
                    </button>
                </div>
            </div>

            <div className="flex items-start gap-3 rounded-2xl border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800 dark:border-blue-900/40 dark:bg-blue-950/20 dark:text-blue-200">
                <Info className="mt-0.5 h-5 w-5 flex-shrink-0" />
                <div>
                    <p>System Admin은 항상 전체 권한을 가집니다.</p>
                    <p className="mt-1">저장한 권한 키는 스캔 업로드, 사용자 관리, 프로젝트 관리 등 실제 API 검사에 바로 사용됩니다.</p>
                    <p className="mt-1">현재 관리 항목은 총 {totalPermissions}개입니다.</p>
                </div>
            </div>

            <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900">
                <table className="w-full border-collapse">
                    <thead className="bg-slate-50 dark:bg-slate-800/70">
                        <tr>
                            <th className="sticky left-0 bg-slate-50 px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 dark:bg-slate-800/70 dark:text-slate-400">권한</th>
                            {roles.map((role) => <th key={role} className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{role}</th>)}
                        </tr>
                    </thead>
                    <tbody>
                        {permissionGroups.map((group) => (
                            <FragmentGroup key={group.name} group={group} matrix={matrix} onToggle={togglePermission} />
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function FragmentGroup({
    group,
    matrix,
    onToggle,
}: {
    group: typeof permissionGroups[number];
    matrix: Record<string, string[]>;
    onToggle: (role: string, permission: string) => void;
}) {
    return (
        <>
            <tr className="bg-slate-100 dark:bg-slate-800">
                <td colSpan={roles.length + 1} className="px-4 py-2 text-sm font-semibold text-slate-700 dark:text-slate-300">{group.name}</td>
            </tr>
            {group.permissions.map(([permission, label]) => (
                <tr key={permission} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="sticky left-0 bg-white px-4 py-3 text-sm text-slate-700 dark:bg-slate-900 dark:text-slate-300">
                        <div className="font-medium">{label}</div>
                        <div className="text-xs text-slate-500 dark:text-slate-500">{permission}</div>
                    </td>
                    {roles.map((role) => {
                        const enabled = role === 'SYSTEM_ADMIN' || (matrix[role] || []).includes(permission);
                        return (
                            <td key={`${role}:${permission}`} className="px-4 py-3 text-center">
                                <button
                                    type="button"
                                    onClick={() => onToggle(role, permission)}
                                    disabled={role === 'SYSTEM_ADMIN'}
                                    className={`inline-flex h-7 w-7 items-center justify-center rounded-lg transition-colors ${
                                        enabled ? 'bg-green-500 text-white' : 'bg-slate-200 text-slate-500 dark:bg-slate-700 dark:text-slate-400'
                                    } ${role === 'SYSTEM_ADMIN' ? 'cursor-not-allowed opacity-80' : 'hover:opacity-80'}`}
                                >
                                    {enabled ? <CheckCircle className="h-4 w-4" /> : <X className="h-4 w-4" />}
                                </button>
                            </td>
                        );
                    })}
                </tr>
            ))}
        </>
    );
}
