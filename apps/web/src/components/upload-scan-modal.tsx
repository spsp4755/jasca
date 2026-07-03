'use client';

import { useState, useCallback, useRef } from 'react';
import {
    X,
    Upload,
    FileJson,
    CheckCircle,
    AlertCircle,
    Loader2,
    ChevronDown,
    FolderPlus,
    FolderOpen,
} from 'lucide-react';
import { useProjects, useOrganizations, useUploadScan, Project, Organization, UploadScanDto } from '@/lib/api-hooks';

interface UploadScanModalProps {
    isOpen: boolean;
    onClose: () => void;
}

const SOURCE_TYPES: { value: UploadScanDto['sourceType']; label: string }[] = [
    { value: 'TRIVY_JSON', label: 'Trivy JSON' },
    { value: 'TRIVY_SARIF', label: 'Trivy SARIF' },
    { value: 'CHECKOV_JSON', label: 'Checkov JSON' },
    { value: 'MANUAL', label: '수동 업로드' },
    { value: 'CI_GITHUB_ACTIONS', label: 'GitHub Actions' },
    { value: 'CI_GITLAB', label: 'GitLab CI' },
    { value: 'CI_JENKINS', label: 'Jenkins' },
    { value: 'CI_BAMBOO', label: 'Bamboo' },
];

type ProjectMode = 'existing' | 'new';
type UploadMode = 'scan-target' | 'json-result';

export function UploadScanModal({ isOpen, onClose }: UploadScanModalProps) {
    const { data: projectsData, isLoading: projectsLoading } = useProjects();
    const { data: organizationsData, isLoading: orgsLoading } = useOrganizations();
    const uploadMutation = useUploadScan();

    // Mode selection
    const [projectMode, setProjectMode] = useState<ProjectMode>('existing');
    const [uploadMode, setUploadMode] = useState<UploadMode>('scan-target');

    // Existing project mode
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');

    // New project mode
    const [newProjectName, setNewProjectName] = useState('');
    const [selectedOrganizationId, setSelectedOrganizationId] = useState<string>('');

    // Common fields
    const [sourceType, setSourceType] = useState<UploadScanDto['sourceType']>('TRIVY_JSON');
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [uploadSuccess, setUploadSuccess] = useState(false);
    const [imageRef, setImageRef] = useState('');
    const [tag, setTag] = useState('');
    const fileInputRef = useRef<HTMLInputElement>(null);

    const projects = projectsData?.data || [];
    const organizations = organizationsData || [];

    const handleDragOver = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(true);
    }, []);

    const handleDragLeave = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
    }, []);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (uploadMode === 'scan-target' || file.type === 'application/json' || file.name.endsWith('.json')) {
                setSelectedFile(file);
            }
        }
    }, [uploadMode]);

    const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const files = e.target.files;
        if (files && files.length > 0) {
            setSelectedFile(files[0]);
        }
    }, []);

    const canSubmit = () => {
        if (!selectedFile) return false;
        if (projectMode === 'existing' && !selectedProjectId) return false;
        if (projectMode === 'new' && (!newProjectName.trim() || !selectedOrganizationId)) return false;
        return true;
    };

    const handleUpload = async () => {
        if (!canSubmit()) return;

        try {
            if (projectMode === 'existing') {
                // Use existing project
                await uploadMutation.mutateAsync({
                    projectId: selectedProjectId,
                    file: selectedFile!,
                    scanTarget: uploadMode === 'scan-target',
                    metadata: {
                        sourceType: uploadMode === 'scan-target' ? 'TRIVY_JSON' : sourceType,
                        imageRef: imageRef || undefined,
                        tag: tag || undefined,
                    },
                });
            } else {
                // Create new project
                await uploadMutation.mutateAsync({
                    file: selectedFile!,
                    scanTarget: uploadMode === 'scan-target',
                    metadata: {
                        sourceType: uploadMode === 'scan-target' ? 'TRIVY_JSON' : sourceType,
                        projectName: newProjectName.trim(),
                        organizationId: selectedOrganizationId,
                        imageRef: imageRef || undefined,
                        tag: tag || undefined,
                    },
                });
            }
            setUploadSuccess(true);
            setTimeout(() => {
                handleClose();
            }, 2000);
        } catch (error) {
            // Error handled by mutation
        }
    };

    const handleClose = () => {
        setProjectMode('existing');
        setUploadMode('scan-target');
        setSelectedProjectId('');
        setNewProjectName('');
        setSelectedOrganizationId('');
        setSourceType('TRIVY_JSON');
        setSelectedFile(null);
        setUploadSuccess(false);
        setImageRef('');
        setTag('');
        uploadMutation.reset();
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                    <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                        Trivy 스캔
                    </h2>
                    <button
                        onClick={handleClose}
                        className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                    >
                        <X className="h-5 w-5 text-slate-500" />
                    </button>
                </div>

                {/* Body */}
                <div className="p-6 space-y-5">
                    {uploadSuccess ? (
                        <div className="flex flex-col items-center justify-center py-8 space-y-4">
                            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center">
                                <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
                            </div>
                            <p className="text-lg font-medium text-slate-900 dark:text-white">
                                업로드 완료!
                            </p>
                            <p className="text-slate-600 dark:text-slate-400 text-center">
                                {projectMode === 'new' ? '프로젝트가 생성되고 ' : ''}
                                {uploadMode === 'scan-target' ? 'Trivy 검사가 완료되었습니다.' : '스캔 결과가 성공적으로 업로드되었습니다.'}
                            </p>
                        </div>
                    ) : (
                        <>
                            {/* Upload Mode Tabs */}
                            <div className="flex rounded-lg bg-slate-100 dark:bg-slate-700 p-1">
                                <button
                                    onClick={() => {
                                        setUploadMode('scan-target');
                                        setSelectedFile(null);
                                    }}
                                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-colors ${uploadMode === 'scan-target'
                                            ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm'
                                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                                        }`}
                                >
                                    <Upload className="h-4 w-4" />
                                    파일 직접 검사
                                </button>
                                <button
                                    onClick={() => {
                                        setUploadMode('json-result');
                                        setSelectedFile(null);
                                    }}
                                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-colors ${uploadMode === 'json-result'
                                            ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm'
                                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                                        }`}
                                >
                                    <FileJson className="h-4 w-4" />
                                    JSON 결과 업로드
                                </button>
                            </div>

                            <div className="rounded-lg border border-blue-200 dark:border-blue-900 bg-blue-50 dark:bg-blue-950/30 px-4 py-3 text-sm text-blue-800 dark:text-blue-300">
                                {uploadMode === 'scan-target'
                                    ? '검사 대상 파일을 업로드하면 서버에서 Trivy로 검사한 뒤 결과를 저장합니다. 업로드 파일은 검사 후 자동 삭제됩니다.'
                                    : '이미 Trivy로 생성한 JSON/SARIF 결과 파일을 그대로 업로드합니다.'}
                            </div>

                            {/* Project Mode Tabs */}
                            <div className="flex rounded-lg bg-slate-100 dark:bg-slate-700 p-1">
                                <button
                                    onClick={() => setProjectMode('existing')}
                                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-colors ${projectMode === 'existing'
                                            ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm'
                                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                                        }`}
                                >
                                    <FolderOpen className="h-4 w-4" />
                                    기존 프로젝트
                                </button>
                                <button
                                    onClick={() => setProjectMode('new')}
                                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-colors ${projectMode === 'new'
                                            ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm'
                                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                                        }`}
                                >
                                    <FolderPlus className="h-4 w-4" />
                                    새 프로젝트
                                </button>
                            </div>

                            {/* Project Selection - Existing Mode */}
                            {projectMode === 'existing' && (
                                <div className="space-y-2">
                                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                        프로젝트 선택 <span className="text-red-500">*</span>
                                    </label>
                                    <div className="relative">
                                        <select
                                            value={selectedProjectId}
                                            onChange={(e) => setSelectedProjectId(e.target.value)}
                                            disabled={projectsLoading}
                                            className="w-full px-4 py-2.5 bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                                        >
                                            <option value="">프로젝트를 선택하세요</option>
                                            {projects.map((project: Project) => (
                                                <option key={project.id} value={project.id}>
                                                    {project.name}
                                                </option>
                                            ))}
                                        </select>
                                        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400 pointer-events-none" />
                                    </div>
                                </div>
                            )}

                            {/* Project Creation - New Mode */}
                            {projectMode === 'new' && (
                                <div className="space-y-4">
                                    <div className="space-y-2">
                                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                            조직 선택 <span className="text-red-500">*</span>
                                        </label>
                                        <div className="relative">
                                            <select
                                                value={selectedOrganizationId}
                                                onChange={(e) => setSelectedOrganizationId(e.target.value)}
                                                disabled={orgsLoading}
                                                className="w-full px-4 py-2.5 bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                                            >
                                                <option value="">조직을 선택하세요</option>
                                                {organizations.map((org: Organization) => (
                                                    <option key={org.id} value={org.id}>
                                                        {org.name}
                                                    </option>
                                                ))}
                                            </select>
                                            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400 pointer-events-none" />
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                            프로젝트 이름 <span className="text-red-500">*</span>
                                        </label>
                                        <input
                                            type="text"
                                            value={newProjectName}
                                            onChange={(e) => setNewProjectName(e.target.value)}
                                            placeholder="my-app"
                                            className="w-full px-4 py-2.5 bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                        <p className="text-xs text-slate-500 dark:text-slate-400">
                                            해당 이름의 프로젝트가 없으면 자동으로 생성됩니다
                                        </p>
                                    </div>
                                </div>
                            )}

                            {/* Source Type Selection */}
                            {uploadMode === 'json-result' && (
                            <div className="space-y-2">
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                    소스 타입
                                </label>
                                <div className="relative">
                                    <select
                                        value={sourceType}
                                        onChange={(e) => setSourceType(e.target.value as UploadScanDto['sourceType'])}
                                        className="w-full px-4 py-2.5 bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    >
                                        {SOURCE_TYPES.map((type) => (
                                            <option key={type.value} value={type.value}>
                                                {type.label}
                                            </option>
                                        ))}
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400 pointer-events-none" />
                                </div>
                            </div>
                            )}

                            {/* Optional Fields */}
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                        이미지 참조 (선택)
                                    </label>
                                    <input
                                        type="text"
                                        value={imageRef}
                                        onChange={(e) => setImageRef(e.target.value)}
                                        placeholder="registry.example.com/app"
                                        className="w-full px-4 py-2.5 bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                        태그 (선택)
                                    </label>
                                    <input
                                        type="text"
                                        value={tag}
                                        onChange={(e) => setTag(e.target.value)}
                                        placeholder="v1.0.0"
                                        className="w-full px-4 py-2.5 bg-slate-50 dark:bg-slate-700 border border-slate-200 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>
                            </div>

                            {/* File Upload Area */}
                            <div className="space-y-2">
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                                    {uploadMode === 'scan-target' ? '검사 대상 파일' : 'JSON/SARIF 결과 파일'} <span className="text-red-500">*</span>
                                </label>
                                <div
                                    onDragOver={handleDragOver}
                                    onDragLeave={handleDragLeave}
                                    onDrop={handleDrop}
                                    onClick={() => fileInputRef.current?.click()}
                                    className={`relative border-2 border-dashed rounded-xl p-8 cursor-pointer transition-all ${isDragging
                                            ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                                            : selectedFile
                                                ? 'border-green-500 bg-green-50 dark:bg-green-900/20'
                                                : 'border-slate-300 dark:border-slate-600 hover:border-blue-400 hover:bg-slate-50 dark:hover:bg-slate-700/50'
                                        }`}
                                >
                                    <input
                                        ref={fileInputRef}
                                        type="file"
                                        accept={uploadMode === 'json-result' ? '.json,.sarif,application/json' : undefined}
                                        onChange={handleFileSelect}
                                        className="hidden"
                                    />
                                    <div className="flex flex-col items-center gap-3 text-center">
                                        {selectedFile ? (
                                            <>
                                                <div className="w-12 h-12 bg-green-100 dark:bg-green-900/50 rounded-full flex items-center justify-center">
                                                    <FileJson className="h-6 w-6 text-green-600 dark:text-green-400" />
                                                </div>
                                                <div>
                                                    <p className="font-medium text-slate-900 dark:text-white">
                                                        {selectedFile.name}
                                                    </p>
                                                    <p className="text-sm text-slate-500">
                                                        {(selectedFile.size / 1024).toFixed(1)} KB
                                                    </p>
                                                </div>
                                            </>
                                        ) : (
                                            <>
                                                <div className="w-12 h-12 bg-slate-100 dark:bg-slate-700 rounded-full flex items-center justify-center">
                                                    <Upload className="h-6 w-6 text-slate-400" />
                                                </div>
                                                <div>
                                                    <p className="font-medium text-slate-900 dark:text-white">
                                                        파일을 드래그하거나 클릭하여 선택
                                                    </p>
                                                    <p className="text-sm text-slate-500">
                                                        {uploadMode === 'scan-target'
                                                            ? 'package-lock.json, pom.xml, requirements.txt, Dockerfile 등 Trivy 지원 파일'
                                                            : 'JSON/SARIF 결과 파일만 지원됩니다'}
                                                    </p>
                                                </div>
                                            </>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Error Message */}
                            {uploadMutation.isError && (
                                <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400">
                                    <AlertCircle className="h-5 w-5 flex-shrink-0" />
                                    <p className="text-sm">{uploadMutation.error?.message || '업로드에 실패했습니다.'}</p>
                                </div>
                            )}
                        </>
                    )}
                </div>

                {/* Footer */}
                {!uploadSuccess && (
                    <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
                        <button
                            onClick={handleClose}
                            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
                        >
                            취소
                        </button>
                        <button
                            onClick={handleUpload}
                            disabled={!canSubmit() || uploadMutation.isPending}
                            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {uploadMutation.isPending ? (
                                <>
                                    <Loader2 className="h-4 w-4 animate-spin" />
                                    {uploadMode === 'scan-target' ? '검사 중...' : '업로드 중...'}
                                </>
                            ) : (
                                <>
                                    <Upload className="h-4 w-4" />
                                    {uploadMode === 'scan-target'
                                        ? (projectMode === 'new' ? '프로젝트 생성 및 검사' : '검사 시작')
                                        : (projectMode === 'new' ? '프로젝트 생성 및 업로드' : '업로드')}
                                </>
                            )}
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
