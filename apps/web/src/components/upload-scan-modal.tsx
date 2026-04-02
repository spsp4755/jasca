'use client';

import { useMemo, useRef, useState } from 'react';
import { AlertCircle, CheckCircle, FileJson, FolderOpen, FolderPlus, Loader2, Trash2, Upload, X } from 'lucide-react';
import { Organization, Project, UploadScanDto, useOrganizations, useProjects, useUploadScan } from '@/lib/api-hooks';

interface UploadScanModalProps {
    isOpen: boolean;
    onClose: () => void;
}

type ProjectMode = 'existing' | 'new';
type FileMeta = Record<string, { displayName: string; description: string }>;

const SOURCE_TYPES: { value: UploadScanDto['sourceType']; label: string }[] = [
    { value: 'TRIVY_JSON', label: 'Trivy JSON' },
    { value: 'TRIVY_SARIF', label: 'Trivy SARIF' },
    { value: 'MANUAL', label: '수동 업로드' },
    { value: 'CI_GITHUB_ACTIONS', label: 'GitHub Actions' },
    { value: 'CI_GITLAB', label: 'GitLab CI' },
    { value: 'CI_JENKINS', label: 'Jenkins' },
    { value: 'CI_BAMBOO', label: 'Bamboo' },
];

const fileKey = (file: File) => `${file.name}:${file.size}:${file.lastModified}`;
const isSupported = (file: File) => file.name.endsWith('.json') || file.name.endsWith('.sarif');

export function UploadScanModal({ isOpen, onClose }: UploadScanModalProps) {
    const { data: projectsData } = useProjects();
    const { data: organizationsData } = useOrganizations();
    const uploadMutation = useUploadScan();
    const inputRef = useRef<HTMLInputElement>(null);

    const [projectMode, setProjectMode] = useState<ProjectMode>('existing');
    const [selectedProjectId, setSelectedProjectId] = useState('');
    const [projectName, setProjectName] = useState('');
    const [organizationId, setOrganizationId] = useState('');
    const [sourceType, setSourceType] = useState<UploadScanDto['sourceType']>('TRIVY_JSON');
    const [imageRef, setImageRef] = useState('');
    const [tag, setTag] = useState('');
    const [files, setFiles] = useState<File[]>([]);
    const [fileMeta, setFileMeta] = useState<FileMeta>({});
    const [summary, setSummary] = useState<{ uploaded: number; failed: { fileName: string; message: string }[]; total: number } | null>(null);

    const projects = projectsData?.data || [];
    const organizations = organizationsData || [];

    const reset = () => {
        setProjectMode('existing');
        setSelectedProjectId('');
        setProjectName('');
        setOrganizationId('');
        setSourceType('TRIVY_JSON');
        setImageRef('');
        setTag('');
        setFiles([]);
        setFileMeta({});
        setSummary(null);
        uploadMutation.reset();
    };

    const close = () => {
        reset();
        onClose();
    };

    const addFiles = (incoming: FileList | File[]) => {
        const next = [...files];
        const nextMeta = { ...fileMeta };
        for (const file of Array.from(incoming).filter(isSupported)) {
            const key = fileKey(file);
            if (!next.some((item) => fileKey(item) === key)) next.push(file);
            if (!nextMeta[key]) nextMeta[key] = { displayName: '', description: '' };
        }
        setFiles(next);
        setFileMeta(nextMeta);
    };

    const canSubmit = useMemo(() => {
        if (!files.length) return false;
        if (projectMode === 'existing') return Boolean(selectedProjectId);
        return Boolean(projectName.trim() && organizationId);
    }, [files.length, organizationId, projectMode, projectName, selectedProjectId]);

    const handleUpload = async () => {
        if (!canSubmit) return;
        try {
            const metadata: UploadScanDto = { sourceType, imageRef: imageRef || undefined, tag: tag || undefined };
            if (projectMode === 'new') {
                metadata.projectName = projectName.trim();
                metadata.organizationId = organizationId;
            }
            const response = await uploadMutation.mutateAsync({
                projectId: projectMode === 'existing' ? selectedProjectId : undefined,
                files,
                metadata,
                entries: files.map((file) => {
                    const meta = fileMeta[fileKey(file)];
                    return {
                        fileName: file.name,
                        displayName: meta?.displayName?.trim() || undefined,
                        description: meta?.description?.trim() || undefined,
                    };
                }),
            });
            setSummary({ uploaded: response.uploaded?.length || 0, failed: response.failed || [], total: response.total || files.length });
            if (!(response.failed || []).length) window.setTimeout(close, 1500);
        } catch (error) {
            // Error state is surfaced by the mutation.
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="w-full max-w-5xl max-h-[90vh] overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-2xl">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-700 px-6 py-4">
                    <div>
                        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">스캔 업로드</h2>
                        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">여러 파일을 한 번에 올리고 파일별 표시 이름과 설명을 남길 수 있습니다.</p>
                    </div>
                    <button type="button" onClick={close} className="rounded-lg p-2 hover:bg-slate-100 dark:hover:bg-slate-800">
                        <X className="h-5 w-5 text-slate-500" />
                    </button>
                </div>
                <div className="max-h-[calc(90vh-144px)] overflow-y-auto p-6">
                    {summary ? (
                        <div className="space-y-4">
                            <div className="flex items-center gap-3 rounded-2xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 p-5">
                                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/30"><CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" /></div>
                                <div>
                                    <p className="font-semibold text-slate-900 dark:text-white">업로드 완료</p>
                                    <p className="text-sm text-slate-500 dark:text-slate-400">총 {summary.total}개 중 {summary.uploaded}개 성공, {summary.failed.length}개 실패</p>
                                </div>
                            </div>
                            {summary.failed.length > 0 && (
                                <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900/40 dark:bg-amber-950/20">
                                    <p className="mb-3 font-medium text-amber-800 dark:text-amber-300">실패한 파일</p>
                                    <div className="space-y-2">
                                        {summary.failed.map((item) => (
                                            <div key={`${item.fileName}:${item.message}`} className="rounded-lg bg-white/80 px-3 py-2 text-sm dark:bg-slate-900/60">
                                                <div className="font-medium text-slate-900 dark:text-white">{item.fileName}</div>
                                                <div className="text-slate-500 dark:text-slate-400">{item.message}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="grid gap-6 lg:grid-cols-[320px_minmax(0,1fr)]">
                            <div className="space-y-4">
                                <div className="rounded-2xl border border-slate-200 dark:border-slate-700 p-4">
                                    <div className="flex gap-2">
                                        <button type="button" onClick={() => setProjectMode('existing')} className={`flex-1 rounded-xl px-3 py-2 text-sm font-medium ${projectMode === 'existing' ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900' : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}><FolderOpen className="mr-2 inline h-4 w-4" />기존</button>
                                        <button type="button" onClick={() => setProjectMode('new')} className={`flex-1 rounded-xl px-3 py-2 text-sm font-medium ${projectMode === 'new' ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900' : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}><FolderPlus className="mr-2 inline h-4 w-4" />신규</button>
                                    </div>
                                    <div className="mt-4 space-y-3">
                                        {projectMode === 'existing' ? (
                                            <select value={selectedProjectId} onChange={(event) => setSelectedProjectId(event.target.value)} className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white">
                                                <option value="">프로젝트 선택</option>
                                                {projects.map((project: Project) => <option key={project.id} value={project.id}>{project.name}</option>)}
                                            </select>
                                        ) : (
                                            <>
                                                <select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white">
                                                    <option value="">조직 선택</option>
                                                    {organizations.map((organization: Organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
                                                </select>
                                                <input value={projectName} onChange={(event) => setProjectName(event.target.value)} placeholder="새 프로젝트 이름" className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white" />
                                            </>
                                        )}
                                        <select value={sourceType} onChange={(event) => setSourceType(event.target.value as UploadScanDto['sourceType'])} className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white">
                                            {SOURCE_TYPES.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
                                        </select>
                                        <input value={imageRef} onChange={(event) => setImageRef(event.target.value)} placeholder="이미지 참조" className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white" />
                                        <input value={tag} onChange={(event) => setTag(event.target.value)} placeholder="태그" className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white" />
                                    </div>
                                </div>
                            </div>
                            <div className="space-y-4">
                                <button type="button" onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); addFiles(event.dataTransfer.files); }} className="w-full rounded-2xl border-2 border-dashed border-slate-300 p-8 text-center hover:border-blue-400 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/70">
                                    <Upload className="mx-auto mb-3 h-8 w-8 text-slate-500" />
                                    <p className="font-medium text-slate-900 dark:text-white">파일을 클릭하거나 끌어오세요</p>
                                    <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">JSON, SARIF 파일 다중 선택 지원</p>
                                    <input ref={inputRef} type="file" multiple accept=".json,.sarif,application/json" onChange={(event) => event.target.files && addFiles(event.target.files)} className="hidden" />
                                </button>
                                <div className="rounded-2xl border border-slate-200 dark:border-slate-700">
                                    <div className="border-b border-slate-200 px-4 py-3 text-sm font-medium text-slate-700 dark:border-slate-700 dark:text-slate-300">선택된 파일 {files.length}개</div>
                                    {files.length === 0 ? <div className="px-4 py-10 text-center text-sm text-slate-500 dark:text-slate-400">선택된 파일이 없습니다.</div> : (
                                        <div className="max-h-[460px] overflow-y-auto divide-y divide-slate-200 dark:divide-slate-700">
                                            {files.map((file) => {
                                                const key = fileKey(file);
                                                const meta = fileMeta[key] || { displayName: '', description: '' };
                                                return (
                                                    <div key={key} className="space-y-3 p-4">
                                                        <div className="flex items-start justify-between gap-3">
                                                            <div className="flex min-w-0 items-start gap-3">
                                                                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 dark:bg-blue-950/30"><FileJson className="h-5 w-5 text-blue-600 dark:text-blue-400" /></div>
                                                                <div className="min-w-0">
                                                                    <p className="truncate font-medium text-slate-900 dark:text-white">{file.name}</p>
                                                                    <p className="text-xs text-slate-500 dark:text-slate-400">{(file.size / 1024).toFixed(1)} KB</p>
                                                                </div>
                                                            </div>
                                                            <button type="button" onClick={() => { setFiles((current) => current.filter((item) => fileKey(item) !== key)); setFileMeta((current) => { const next = { ...current }; delete next[key]; return next; }); }} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-red-500 dark:hover:bg-slate-800"><Trash2 className="h-4 w-4" /></button>
                                                        </div>
                                                        <div className="grid gap-3 md:grid-cols-2">
                                                            <input value={meta.displayName} onChange={(event) => setFileMeta((current) => ({ ...current, [key]: { ...meta, displayName: event.target.value } }))} placeholder="표시 이름" className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-white" />
                                                            <input value={meta.description} onChange={(event) => setFileMeta((current) => ({ ...current, [key]: { ...meta, description: event.target.value } }))} placeholder="설명" className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-white" />
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    )}
                                </div>
                                {uploadMutation.isError && <div className="flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/20 dark:text-red-300"><AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0" />{uploadMutation.error?.message || '업로드 중 오류가 발생했습니다.'}</div>}
                            </div>
                        </div>
                    )}
                </div>
                {!summary && (
                    <div className="flex items-center justify-end gap-3 border-t border-slate-200 bg-slate-50 px-6 py-4 dark:border-slate-700 dark:bg-slate-900/70">
                        <button type="button" onClick={close} className="rounded-xl px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 dark:text-slate-300 dark:hover:bg-slate-800">취소</button>
                        <button type="button" onClick={handleUpload} disabled={!canSubmit || uploadMutation.isPending} className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50">
                            {uploadMutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin" />업로드 중</> : <><Upload className="h-4 w-4" />{files.length > 1 ? `${files.length}개 업로드` : '업로드'}</>}
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
