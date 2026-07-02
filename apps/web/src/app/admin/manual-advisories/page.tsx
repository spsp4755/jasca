'use client';

import { useMemo, useRef, useState } from 'react';
import { AlertTriangle, Edit, Loader2, Plus, Search, ShieldAlert, Trash2, Upload, X } from 'lucide-react';
import {
    ManualAdvisory,
    ManualAdvisoryInput,
    useCreateManualAdvisory,
    useDeleteManualAdvisory,
    useBulkUploadManualAdvisories,
    useManualAdvisories,
    useOrganizations,
    useProjects,
    useUpdateManualAdvisory,
} from '@/lib/api-hooks';

const SEVERITIES: ManualAdvisory['severity'][] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

const emptyForm: ManualAdvisoryInput = {
    advisoryId: '',
    cveId: '',
    title: '',
    description: '',
    severity: 'HIGH',
    packageName: '',
    affectedVersionRange: '*',
    fixedVersion: '',
    remediation: '',
    references: [],
    isActive: true,
    organizationId: '',
    projectId: '',
};

function severityClass(severity: string) {
    switch (severity) {
        case 'CRITICAL':
            return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
        case 'HIGH':
            return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300';
        case 'MEDIUM':
            return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300';
        case 'LOW':
            return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300';
        default:
            return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300';
    }
}

export default function AdminManualAdvisoriesPage() {
    const { data: advisories, isLoading, error } = useManualAdvisories();
    const { data: organizations } = useOrganizations();
    const { data: projectsData } = useProjects();
    const createMutation = useCreateManualAdvisory();
    const updateMutation = useUpdateManualAdvisory();
    const deleteMutation = useDeleteManualAdvisory();
    const bulkUploadMutation = useBulkUploadManualAdvisories();

    const fileInputRef = useRef<HTMLInputElement>(null);
    const [search, setSearch] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [editing, setEditing] = useState<ManualAdvisory | null>(null);
    const [form, setForm] = useState<ManualAdvisoryInput>(emptyForm);
    const [referencesText, setReferencesText] = useState('');

    const projects = projectsData?.data || [];
    const filtered = useMemo(() => {
        const query = search.trim().toLowerCase();
        if (!query) return advisories || [];
        return (advisories || []).filter((advisory) =>
            [
                advisory.advisoryId,
                advisory.cveId,
                advisory.title,
                advisory.packageName,
                advisory.affectedVersionRange,
                advisory.organization?.name,
                advisory.project?.name,
            ].filter(Boolean).some((value) => String(value).toLowerCase().includes(query)),
        );
    }, [advisories, search]);

    const stats = useMemo(() => {
        const list = advisories || [];
        return {
            total: list.length,
            active: list.filter((item) => item.isActive).length,
            critical: list.filter((item) => item.severity === 'CRITICAL').length,
            scoped: list.filter((item) => item.organizationId || item.projectId).length,
        };
    }, [advisories]);

    const openCreate = () => {
        setEditing(null);
        setForm(emptyForm);
        setReferencesText('');
        setShowModal(true);
    };

    const openEdit = (advisory: ManualAdvisory) => {
        setEditing(advisory);
        setForm({
            advisoryId: advisory.advisoryId,
            cveId: advisory.cveId || '',
            title: advisory.title,
            description: advisory.description || '',
            severity: advisory.severity,
            packageName: advisory.packageName,
            affectedVersionRange: advisory.affectedVersionRange,
            fixedVersion: advisory.fixedVersion || '',
            remediation: advisory.remediation || '',
            references: advisory.references || [],
            isActive: advisory.isActive,
            organizationId: advisory.organizationId || '',
            projectId: advisory.projectId || '',
        });
        setReferencesText((advisory.references || []).join('\n'));
        setShowModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setEditing(null);
    };

    const save = async () => {
        const payload: ManualAdvisoryInput = {
            ...form,
            organizationId: form.organizationId || undefined,
            projectId: form.projectId || undefined,
            references: referencesText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
        };

        if (editing) {
            await updateMutation.mutateAsync({ id: editing.id, ...payload });
        } else {
            await createMutation.mutateAsync(payload);
        }
        closeModal();
    };

    const remove = async (advisory: ManualAdvisory) => {
        if (!confirm(`${advisory.advisoryId} 수동 취약점을 삭제하시겠습니까?`)) return;
        await deleteMutation.mutateAsync(advisory.id);
    };

    const uploadBulkFile = async (file?: File) => {
        if (!file) return;
        const result = await bulkUploadMutation.mutateAsync(file) as {
            created: number;
            updated: number;
            failed: number;
            errors?: Array<{ index: number; advisoryId?: string; message: string }>;
        };
        const failedMessage = result.failed > 0
            ? `\n실패 ${result.failed}건:\n${result.errors?.slice(0, 5).map((error) => `${error.index + 1}행 ${error.advisoryId || ''} ${error.message}`).join('\n') || ''}`
            : '';
        alert(`수동 Advisory 반입 완료\n생성 ${result.created}건, 수정 ${result.updated}건${failedMessage}`);
        if (fileInputRef.current) fileInputRef.current.value = '';
    };

    if (isLoading) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-red-600" />
            </div>
        );
    }

    if (error) {
        return (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
                수동 취약점 목록을 불러오지 못했습니다.
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="rounded-xl bg-gradient-to-r from-red-500 to-orange-500 p-3">
                        <ShieldAlert className="h-6 w-6 text-white" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">수동 취약점 Advisory</h1>
                        <p className="text-sm text-slate-500">Trivy DB에 없는 사내/긴급 취약점을 패키지와 버전 기준으로 추가 탐지합니다.</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".csv,.json,application/json,text/csv"
                        className="hidden"
                        onChange={(event) => uploadBulkFile(event.target.files?.[0])}
                    />
                    <button
                        onClick={() => fileInputRef.current?.click()}
                        disabled={bulkUploadMutation.isPending}
                        className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                    >
                        {bulkUploadMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                        CSV/JSON 가져오기
                    </button>
                    <button
                        onClick={openCreate}
                        className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
                    >
                        <Plus className="h-4 w-4" />
                        Advisory 추가
                    </button>
                </div>
            </div>

            <div className="grid gap-4 md:grid-cols-4">
                {[
                    ['전체', stats.total],
                    ['활성', stats.active],
                    ['Critical', stats.critical],
                    ['범위 지정', stats.scoped],
                ].map(([label, value]) => (
                    <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
                        <p className="text-sm text-slate-500">{label}</p>
                        <p className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{value}</p>
                    </div>
                ))}
            </div>

            <div className="rounded-xl border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800 dark:border-blue-900 dark:bg-blue-900/20 dark:text-blue-200">
                등록된 Advisory는 새 스캔 저장 시 Trivy 결과의 패키지 목록과 매칭됩니다. CSV/JSON 대량 반입도 가능하며, 동일한 Advisory ID가 있으면 기존 항목을 수정합니다.
            </div>

            <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-800">
                <div className="border-b border-slate-200 p-4 dark:border-slate-700">
                    <div className="relative">
                        <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                        <input
                            value={search}
                            onChange={(event) => setSearch(event.target.value)}
                            placeholder="Advisory ID, CVE, 패키지명, 제목 검색..."
                            className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-sm outline-none focus:ring-2 focus:ring-red-500 dark:border-slate-700 dark:bg-slate-900 dark:text-white"
                        />
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead className="bg-slate-50 text-left text-slate-500 dark:bg-slate-900/60">
                            <tr>
                                <th className="px-4 py-3">Advisory</th>
                                <th className="px-4 py-3">패키지/버전</th>
                                <th className="px-4 py-3">심각도</th>
                                <th className="px-4 py-3">범위</th>
                                <th className="px-4 py-3">상태</th>
                                <th className="px-4 py-3 text-right">작업</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                            {filtered.map((advisory) => (
                                <tr key={advisory.id} className="text-slate-700 dark:text-slate-300">
                                    <td className="px-4 py-3">
                                        <p className="font-medium text-slate-900 dark:text-white">{advisory.title}</p>
                                        <p className="text-xs text-slate-500">{advisory.advisoryId}{advisory.cveId ? ` / ${advisory.cveId}` : ''}</p>
                                    </td>
                                    <td className="px-4 py-3">
                                        <p className="font-mono text-xs">{advisory.packageName}</p>
                                        <p className="text-xs text-slate-500">{advisory.affectedVersionRange} → {advisory.fixedVersion || '수정 버전 미정'}</p>
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={`rounded-full px-2 py-1 text-xs font-medium ${severityClass(advisory.severity)}`}>
                                            {advisory.severity}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-xs">
                                        {advisory.project?.name || advisory.organization?.name || '전체'}
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={`rounded-full px-2 py-1 text-xs ${advisory.isActive ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}`}>
                                            {advisory.isActive ? '활성' : '비활성'}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3">
                                        <div className="flex justify-end gap-2">
                                            <button onClick={() => openEdit(advisory)} className="rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-slate-700">
                                                <Edit className="h-4 w-4" />
                                            </button>
                                            <button onClick={() => remove(advisory)} className="rounded p-1 text-slate-500 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20">
                                                <Trash2 className="h-4 w-4" />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {filtered.length === 0 && (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12 text-center text-slate-500">
                                        등록된 수동 Advisory가 없습니다.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {showModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-xl bg-white shadow-xl dark:bg-slate-800">
                        <div className="sticky top-0 flex items-center justify-between border-b border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-800">
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                                {editing ? 'Advisory 수정' : 'Advisory 추가'}
                            </h2>
                            <button onClick={closeModal} className="text-slate-400 hover:text-slate-600">
                                <X className="h-5 w-5" />
                            </button>
                        </div>

                        <div className="grid gap-4 p-6 md:grid-cols-2">
                            <Field label="Advisory ID *">
                                <input value={form.advisoryId} onChange={(e) => setForm({ ...form, advisoryId: e.target.value })} className="input" placeholder="KCB-ADV-2026-001" />
                            </Field>
                            <Field label="CVE ID">
                                <input value={form.cveId} onChange={(e) => setForm({ ...form, cveId: e.target.value })} className="input" placeholder="CVE-2026-0001 또는 빈 값" />
                            </Field>
                            <Field label="제목 *">
                                <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} className="input" placeholder="사내 긴급 취약점" />
                            </Field>
                            <Field label="심각도 *">
                                <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value as ManualAdvisory['severity'] })} className="input">
                                    {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
                                </select>
                            </Field>
                            <Field label="패키지명 *">
                                <input value={form.packageName} onChange={(e) => setForm({ ...form, packageName: e.target.value })} className="input" placeholder="log4j-core 또는 lodash" />
                            </Field>
                            <Field label="영향 버전 범위">
                                <input value={form.affectedVersionRange} onChange={(e) => setForm({ ...form, affectedVersionRange: e.target.value })} className="input" placeholder="<2.17.1, >=1.0.0 <1.2.3, *" />
                            </Field>
                            <Field label="수정 버전">
                                <input value={form.fixedVersion} onChange={(e) => setForm({ ...form, fixedVersion: e.target.value })} className="input" placeholder="2.17.1" />
                            </Field>
                            <Field label="범위">
                                <select
                                    value={form.projectId ? `project:${form.projectId}` : form.organizationId ? `org:${form.organizationId}` : 'global'}
                                    onChange={(e) => {
                                        const [type, id] = e.target.value.split(':');
                                        setForm({
                                            ...form,
                                            organizationId: type === 'org' ? id : '',
                                            projectId: type === 'project' ? id : '',
                                        });
                                    }}
                                    className="input"
                                >
                                    <option value="global">전체</option>
                                    {organizations?.map((org) => <option key={org.id} value={`org:${org.id}`}>조직: {org.name}</option>)}
                                    {projects.map((project) => <option key={project.id} value={`project:${project.id}`}>프로젝트: {project.name}</option>)}
                                </select>
                            </Field>
                            <div className="md:col-span-2">
                                <Field label="설명">
                                    <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="input min-h-20" />
                                </Field>
                            </div>
                            <div className="md:col-span-2">
                                <Field label="조치 가이드">
                                    <textarea value={form.remediation} onChange={(e) => setForm({ ...form, remediation: e.target.value })} className="input min-h-20" placeholder="업그레이드, 설정 변경, 임시 우회 방안 등" />
                                </Field>
                            </div>
                            <div className="md:col-span-2">
                                <Field label="참고 URL">
                                    <textarea value={referencesText} onChange={(e) => setReferencesText(e.target.value)} className="input min-h-20" placeholder="한 줄에 하나씩 입력" />
                                </Field>
                            </div>
                            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                                <input type="checkbox" checked={form.isActive} onChange={(e) => setForm({ ...form, isActive: e.target.checked })} />
                                활성화
                            </label>
                        </div>

                        <div className="sticky bottom-0 flex justify-between border-t border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-800">
                            <div className="flex items-center gap-2 text-xs text-slate-500">
                                <AlertTriangle className="h-4 w-4" />
                                저장 후 새 스캔부터 매칭됩니다. 기존 스캔은 재스캔해야 반영됩니다.
                            </div>
                            <div className="flex gap-2">
                                <button onClick={closeModal} className="rounded-lg border border-slate-200 px-4 py-2 text-sm dark:border-slate-700">취소</button>
                                <button
                                    onClick={save}
                                    disabled={!form.advisoryId || !form.title || !form.packageName || createMutation.isPending || updateMutation.isPending}
                                    className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                                >
                                    {createMutation.isPending || updateMutation.isPending ? '저장 중...' : '저장'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <style jsx>{`
                .input {
                    width: 100%;
                    border-radius: 0.5rem;
                    border: 1px solid rgb(226 232 240);
                    background: rgb(248 250 252);
                    padding: 0.625rem 0.75rem;
                    color: rgb(15 23 42);
                    outline: none;
                }
                .input:focus {
                    box-shadow: 0 0 0 2px rgb(239 68 68);
                }
                :global(.dark) .input {
                    border-color: rgb(51 65 85);
                    background: rgb(15 23 42);
                    color: white;
                }
            `}</style>
        </div>
    );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <label className="block">
            <span className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">{label}</span>
            {children}
        </label>
    );
}
