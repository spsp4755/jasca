'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Archive, ArrowLeft, CheckCircle, FileJson, Loader2, ShieldCheck, Upload, AlertCircle } from 'lucide-react';
import Link from 'next/link';
import { useCancelTrivyScan, useOrganizations, useProjects, useUploadScan } from '@/lib/api-hooks';
import type { TrivyScanOptions } from '@/lib/api-hooks';

type UploadMode = 'scan-target' | 'result-file';
type SourceType = 'TRIVY_JSON' | 'TRIVY_SARIF' | 'MANUAL';

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const SCANNER_OPTIONS = [
    { value: 'vuln', label: '취약점(vuln)' },
    { value: 'license', label: '라이선스(license)' },
    { value: 'misconfig', label: '설정오류(misconfig)' },
    { value: 'secret', label: '시크릿(secret)' },
];

const SCAN_MODE_OPTIONS = [
    { value: 'auto', label: 'Auto', description: '업로드 파일을 보고 image/rootfs/fs/rpm 보조 흐름을 자동 선택합니다.' },
    { value: 'fs', label: 'Filesystem(fs)', description: '소스코드, manifest, 일반 압축 해제 결과, 단일 패키지 파일을 검사합니다.' },
    { value: 'rootfs', label: 'Rootfs', description: 'OS 패키지 DB가 포함된 Linux root filesystem 압축본을 검사합니다.' },
    { value: 'image', label: 'Image archive', description: 'Docker/OCI image tar 또는 tar.gz를 trivy image --input 방식으로 검사합니다.' },
    { value: 'repo', label: 'Repository(repo)', description: '업로드한 소스 저장소 압축본을 해제한 뒤 trivy repo로 검사합니다.' },
    { value: 'sbom', label: 'SBOM', description: 'CycloneDX, SPDX 등 이미 생성된 SBOM 파일을 trivy sbom으로 검사합니다.' },
    { value: 'vm', label: 'VM image', description: 'qcow2, vmdk, vhd, raw img 같은 VM 이미지를 trivy vm으로 검사합니다.' },
    { value: 'rpm', label: 'RPM helper', description: 'RPM 페이로드를 rpm2cpio | cpio로 추출한 뒤 trivy fs로 검사합니다. RPM 내부에 포함된 Go/Java 등 바이너리까지 분석됩니다.' },
] as const;

const ANALYSIS_STRATEGY_OPTIONS = [
    { value: 'auto', label: '폐쇄망 자동 보강', description: 'Trivy 직접 검사 결과가 비어 있거나 패키지를 못 찾으면 Syft SBOM 생성 후 trivy sbom으로 재검사합니다.' },
    { value: 'direct', label: 'Trivy 직접 검사만', description: 'Syft를 사용하지 않고 선택한 Trivy 모드로만 검사합니다.' },
    { value: 'syft-sbom', label: 'Syft SBOM 우선', description: '파일/압축을 Syft로 SBOM 생성한 뒤 trivy sbom으로 검사합니다. fs/rootfs/repo 모드에서 사용합니다.' },
] as const;

export default function NewScanPage() {
    const router = useRouter();
    const [uploadMode, setUploadMode] = useState<UploadMode>('scan-target');
    const [file, setFile] = useState<File | null>(null);
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');
    const [selectedOrgId, setSelectedOrgId] = useState<string>('');
    const [projectName, setProjectName] = useState<string>('');
    const [sourceType, setSourceType] = useState<SourceType>('TRIVY_JSON');
    const [dragActive, setDragActive] = useState(false);
    const [uploadStatus, setUploadStatus] = useState<'idle' | 'uploading' | 'cancelling' | 'success' | 'error'>('idle');
    const [errorMessage, setErrorMessage] = useState<string>('');
    const [scanOperationId, setScanOperationId] = useState<string>('');
    const isPageActiveRef = useRef(true);
    const cancelRequestedRef = useRef(false);
    const uploadAbortControllerRef = useRef<AbortController | null>(null);
    const redirectTimeoutRef = useRef<number | null>(null);
    const [trivyOptions, setTrivyOptions] = useState<Required<TrivyScanOptions>>({
        scanMode: 'fs',
        analysisStrategy: 'auto',
        rpmOsFamily: 'redhat',
        rpmOsVersion: '',
        offlineScan: true,
        skipDbUpdate: true,
        skipJavaDbUpdate: true,
        ignoreUnfixed: false,
        severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        scanners: ['vuln', 'license'],
        timeout: '10m',
    });

    const { data: projectsData } = useProjects();
    const { data: orgsData } = useOrganizations();
    const uploadMutation = useUploadScan();
    const cancelScanMutation = useCancelTrivyScan();

    const projects = projectsData?.data || [];
    const organizations = orgsData || [];
    const isScanningTarget = uploadMode === 'scan-target';
    const acceptedFiles = isScanningTarget
        ? '.zip,.tar,.tar.gz,.tgz,.rpm,.deb,.apk,.jar,.war,.ear,.gem,.whl,.egg,.nupkg,.json,.spdx,.cdx,.cyclonedx,.lock,.txt,.xml,.gradle,.pom,.csproj,.sln,.yaml,.yml,.toml,.qcow2,.vmdk,.vhd,.vhdx,.img,Dockerfile'
        : '.json,.sarif';

    useEffect(() => {
        isPageActiveRef.current = true;

        return () => {
            isPageActiveRef.current = false;
            if (redirectTimeoutRef.current) {
                window.clearTimeout(redirectTimeoutRef.current);
            }
        };
    }, []);

    const resetFileState = () => {
        setFile(null);
        setUploadStatus('idle');
        setErrorMessage('');
    };

    const handleModeChange = (mode: UploadMode) => {
        setUploadMode(mode);
        resetFileState();
        if (mode === 'scan-target') {
            setSourceType('TRIVY_JSON');
        }
    };

    const handleDrag = (e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(e.type === 'dragenter' || e.type === 'dragover');
    };

    const isAllowedFile = (candidate: File) => {
        const name = candidate.name.toLowerCase();
        if (isScanningTarget) {
            return true;
        }
        return name.endsWith('.json') || name.endsWith('.sarif');
    };

    const selectFile = (candidate: File) => {
        if (!isAllowedFile(candidate)) {
            setErrorMessage('결과 업로드 모드에서는 JSON 또는 SARIF 파일만 업로드할 수 있습니다.');
            return;
        }

        setFile(candidate);
        setUploadStatus('idle');
        setErrorMessage('');
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            selectFile(e.dataTransfer.files[0]);
        }
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            selectFile(e.target.files[0]);
        }
    };

    const toggleListOption = (key: 'severities' | 'scanners', value: string) => {
        setTrivyOptions((current) => {
            const selected = current[key];
            const next = selected.includes(value)
                ? selected.filter((item) => item !== value)
                : [...selected, value];

            return { ...current, [key]: next };
        });
    };

    const handleUpload = async () => {
        if (!file) {
            setErrorMessage('업로드할 파일을 선택해주세요.');
            return;
        }

        if (!selectedProjectId && !projectName.trim()) {
            setErrorMessage('프로젝트를 선택하거나 새 프로젝트 이름을 입력해주세요.');
            return;
        }

        if (isScanningTarget && trivyOptions.scanners.length === 0) {
            setErrorMessage('Trivy scanner를 최소 1개 이상 선택해주세요.');
            return;
        }

        if (isScanningTarget && trivyOptions.severities.length === 0) {
            setErrorMessage('심각도를 최소 1개 이상 선택해주세요.');
            return;
        }

        setUploadStatus('uploading');
        setErrorMessage('');
        cancelRequestedRef.current = false;
        uploadAbortControllerRef.current?.abort();
        const uploadAbortController = new AbortController();
        uploadAbortControllerRef.current = uploadAbortController;
        const nextOperationId = isScanningTarget
            ? (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`)
            : '';
        setScanOperationId(nextOperationId);

        try {
            const scanResult = await uploadMutation.mutateAsync({
                projectId: selectedProjectId || undefined,
                file,
                scanTarget: isScanningTarget,
                trivyOptions: isScanningTarget ? trivyOptions : undefined,
                scanOperationId: nextOperationId || undefined,
                signal: uploadAbortController.signal,
                metadata: {
                    sourceType: isScanningTarget ? 'TRIVY_JSON' : sourceType,
                    projectName: !selectedProjectId ? projectName.trim() : undefined,
                    organizationId: selectedOrgId || undefined,
                    imageRef: file.name,
                },
            });

            if (!isPageActiveRef.current) return;

            setUploadStatus('success');
            setScanOperationId('');
            uploadAbortControllerRef.current = null;
            const destination = scanResult?.id ? `/dashboard/scans/${scanResult.id}` : '/dashboard/scans';
            redirectTimeoutRef.current = window.setTimeout(() => {
                if (isPageActiveRef.current) {
                    router.push(destination);
                }
            }, 1500);
        } catch (error: any) {
            if (!isPageActiveRef.current) return;

            setScanOperationId('');
            if (cancelRequestedRef.current) {
                setUploadStatus('idle');
                setErrorMessage('검사를 중지했습니다. 임시 업로드 파일은 서버에서 정리됩니다.');
                return;
            }

            setUploadStatus('error');
            setErrorMessage(error.message || '업로드 또는 스캔에 실패했습니다.');
        }
    };

    const handleCancelScan = async () => {
        if (!scanOperationId) return;

        cancelRequestedRef.current = true;
        setUploadStatus('cancelling');
        setErrorMessage('');

        try {
            const result = await cancelScanMutation.mutateAsync(scanOperationId);
            uploadAbortControllerRef.current?.abort();
            setScanOperationId('');
            setUploadStatus('idle');
            setErrorMessage((result as any)?.cancelled === false
                ? '실행 중인 Trivy 스캔을 찾지 못했습니다. 잠시 후 결과 목록을 새로고침해 주세요.'
                : '검사를 중지했습니다. 임시 업로드 파일은 서버에서 정리됩니다.');
        } catch (error: any) {
            setUploadStatus('uploading');
            setErrorMessage(error.message || '검사 중지 요청에 실패했습니다.');
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 p-6">
            <div className="mx-auto max-w-4xl">
                <div className="mb-8">
                    <Link
                        href="/dashboard/scans"
                        className="mb-4 inline-flex items-center gap-2 text-slate-400 transition-colors hover:text-white"
                    >
                        <ArrowLeft className="h-4 w-4" />
                        스캔 목록으로 돌아가기
                    </Link>
                    <h1 className="text-2xl font-bold text-white">새 스캔 등록</h1>
                    <p className="mt-2 text-slate-400">
                        폐쇄망 환경에서는 검사 대상 파일이나 압축 파일을 업로드해 JASCA 서버 안의 Trivy로 바로 검사할 수 있습니다.
                    </p>
                </div>

                <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
                        <div className="mb-6 grid gap-3 sm:grid-cols-2">
                            <button
                                type="button"
                                onClick={() => handleModeChange('scan-target')}
                                className={`rounded-xl border p-4 text-left transition ${
                                    isScanningTarget
                                        ? 'border-blue-500 bg-blue-500/10 text-white'
                                        : 'border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-500'
                                }`}
                            >
                                <ShieldCheck className="mb-3 h-6 w-6 text-blue-300" />
                                <div className="font-semibold">Trivy로 직접 검사</div>
                                <div className="mt-1 text-sm text-slate-400">파일, .zip, .tar, .tar.gz를 업로드하면 서버에서 검사합니다.</div>
                            </button>
                            <button
                                type="button"
                                onClick={() => handleModeChange('result-file')}
                                className={`rounded-xl border p-4 text-left transition ${
                                    !isScanningTarget
                                        ? 'border-emerald-500 bg-emerald-500/10 text-white'
                                        : 'border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-500'
                                }`}
                            >
                                <FileJson className="mb-3 h-6 w-6 text-emerald-300" />
                                <div className="font-semibold">결과 파일 업로드</div>
                                <div className="mt-1 text-sm text-slate-400">이미 생성된 Trivy JSON 또는 SARIF 결과를 등록합니다.</div>
                            </button>
                        </div>

                        <div
                            className={`relative rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
                                dragActive ? 'border-blue-500 bg-blue-500/10' : 'border-slate-700 hover:border-slate-500'
                            } ${file ? 'border-green-500 bg-green-500/10' : ''}`}
                            onDragEnter={handleDrag}
                            onDragLeave={handleDrag}
                            onDragOver={handleDrag}
                            onDrop={handleDrop}
                        >
                            <input
                                type="file"
                                accept={acceptedFiles}
                                onChange={handleFileChange}
                                className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
                            />

                            {file ? (
                                <div className="flex flex-col items-center gap-3">
                                    {isScanningTarget ? <Archive className="h-12 w-12 text-green-400" /> : <FileJson className="h-12 w-12 text-green-400" />}
                                    <div>
                                        <p className="font-medium text-white">{file.name}</p>
                                        <p className="text-sm text-slate-400">{(file.size / 1024).toFixed(1)} KB</p>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            resetFileState();
                                        }}
                                        className="text-sm text-slate-400 hover:text-white"
                                    >
                                        다른 파일 선택
                                    </button>
                                </div>
                            ) : (
                                <div className="flex flex-col items-center gap-3">
                                    <Upload className="h-12 w-12 text-slate-500" />
                                    <div>
                                        <p className="text-white">여기로 파일을 드래그하거나 클릭해서 선택</p>
                                        <p className="mt-1 text-sm text-slate-400">
                                            {isScanningTarget ? '.zip, .tar, .tar.gz, 일반 파일 지원' : 'JSON 또는 SARIF 결과 파일 지원'}
                                        </p>
                                    </div>
                                </div>
                            )}
                        </div>

                        {!isScanningTarget && (
                            <div className="mt-6">
                                <label className="mb-2 block text-sm font-medium text-slate-300">소스 유형</label>
                                <select
                                    value={sourceType}
                                    onChange={(e) => setSourceType(e.target.value as SourceType)}
                                    className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    <option value="TRIVY_JSON">Trivy JSON</option>
                                    <option value="TRIVY_SARIF">Trivy SARIF</option>
                                    <option value="MANUAL">수동 업로드</option>
                                </select>
                            </div>
                        )}

                        <div className="mt-6">
                            <label className="mb-2 block text-sm font-medium text-slate-300">프로젝트</label>
                            <select
                                value={selectedProjectId}
                                onChange={(e) => setSelectedProjectId(e.target.value)}
                                className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            >
                                <option value="">새 프로젝트 생성</option>
                                {projects.map((project) => (
                                    <option key={project.id} value={project.id}>
                                        {project.name}
                                    </option>
                                ))}
                            </select>
                        </div>

                        {!selectedProjectId && (
                            <>
                                <div className="mt-4">
                                    <label className="mb-2 block text-sm font-medium text-slate-300">새 프로젝트 이름</label>
                                    <input
                                        type="text"
                                        value={projectName}
                                        onChange={(e) => setProjectName(e.target.value)}
                                        placeholder="예: customer-portal"
                                        className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                </div>

                                <div className="mt-4">
                                    <label className="mb-2 block text-sm font-medium text-slate-300">조직</label>
                                    <select
                                        value={selectedOrgId}
                                        onChange={(e) => setSelectedOrgId(e.target.value)}
                                        className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    >
                                        <option value="">조직 선택 안 함</option>
                                        {organizations.map((org) => (
                                            <option key={org.id} value={org.id}>
                                                {org.name}
                                            </option>
                                        ))}
                                    </select>
                                </div>
                            </>
                        )}

                        {errorMessage && (
                            <div className="mt-4 flex items-center gap-2 rounded-lg border border-red-500/50 bg-red-500/20 p-3 text-red-300">
                                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                                <span className="text-sm">{errorMessage}</span>
                            </div>
                        )}

                        {uploadStatus === 'success' && (
                            <div className="mt-4 flex items-center gap-2 rounded-lg border border-green-500/50 bg-green-500/20 p-3 text-green-300">
                                <CheckCircle className="h-4 w-4 flex-shrink-0" />
                                <span className="text-sm">처리가 완료되었습니다. 스캔 목록으로 이동합니다.</span>
                            </div>
                        )}

                        <button
                            type="button"
                            onClick={handleUpload}
                            disabled={uploadStatus === 'uploading' || uploadStatus === 'cancelling' || uploadStatus === 'success' || !file}
                            className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 py-3 font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-700"
                        >
                            {uploadStatus === 'uploading' ? (
                                <>
                                    <Loader2 className="h-5 w-5 animate-spin" />
                                    {isScanningTarget ? 'Trivy 검사 중...' : '업로드 중...'}
                                </>
                            ) : uploadStatus === 'success' ? (
                                <>
                                    <CheckCircle className="h-5 w-5" />
                                    완료
                                </>
                            ) : (
                                <>
                                    <Upload className="h-5 w-5" />
                                    {isScanningTarget ? 'Trivy 검사 실행' : '결과 업로드'}
                                </>
                            )}
                        </button>

                        {isScanningTarget && (uploadStatus === 'uploading' || uploadStatus === 'cancelling') && (
                            <button
                                type="button"
                                onClick={handleCancelScan}
                                disabled={uploadStatus === 'cancelling'}
                                className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-red-500/60 bg-red-500/10 py-3 font-medium text-red-200 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                                {uploadStatus === 'cancelling' ? (
                                    <>
                                        <Loader2 className="h-5 w-5 animate-spin" />
                                        중지 요청 중...
                                    </>
                                ) : (
                                    <>
                                        <AlertCircle className="h-5 w-5" />
                                        검사 중지
                                    </>
                                )}
                            </button>
                        )}
                    </div>

                    <aside className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
                        <h2 className="text-lg font-semibold text-white">Trivy 실행 옵션</h2>
                        <p className="mt-2 text-sm text-slate-400">
                            폐쇄망 기본값은 DB 다운로드를 시도하지 않도록 설정되어 있습니다.
                        </p>

                        <div className={`mt-5 space-y-4 ${!isScanningTarget ? 'pointer-events-none opacity-50' : ''}`}>
                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-300">Scan mode</label>
                                <select
                                    value={trivyOptions.scanMode}
                                    onChange={(e) => setTrivyOptions((current) => ({ ...current, scanMode: e.target.value as Required<TrivyScanOptions>['scanMode'] }))}
                                    className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    {SCAN_MODE_OPTIONS.map((mode) => (
                                        <option key={mode.value} value={mode.value}>
                                            {mode.label}
                                        </option>
                                    ))}
                                </select>
                                <p className="mt-1 text-xs text-slate-500">
                                    {SCAN_MODE_OPTIONS.find((mode) => mode.value === trivyOptions.scanMode)?.description}
                                </p>
                            </div>

                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-300">Analysis strategy</label>
                                <select
                                    value={trivyOptions.analysisStrategy}
                                    onChange={(e) => setTrivyOptions((current) => ({ ...current, analysisStrategy: e.target.value as Required<TrivyScanOptions>['analysisStrategy'] }))}
                                    className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    {ANALYSIS_STRATEGY_OPTIONS.map((strategy) => (
                                        <option key={strategy.value} value={strategy.value}>
                                            {strategy.label}
                                        </option>
                                    ))}
                                </select>
                                <p className="mt-1 text-xs text-slate-500">
                                    {ANALYSIS_STRATEGY_OPTIONS.find((strategy) => strategy.value === trivyOptions.analysisStrategy)?.description}
                                </p>
                            </div>

                            {(trivyOptions.scanMode === 'auto' || trivyOptions.scanMode === 'rpm') && (
                                <div className="grid gap-3 sm:grid-cols-2">
                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">RPM OS family</label>
                                        <input
                                            type="text"
                                            value={trivyOptions.rpmOsFamily}
                                            onChange={(e) => setTrivyOptions((current) => ({ ...current, rpmOsFamily: e.target.value }))}
                                            placeholder="redhat"
                                            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                        <p className="mt-1 text-xs text-slate-500">예: redhat, centos, rocky, alma</p>
                                    </div>
                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">RPM OS version</label>
                                        <input
                                            type="text"
                                            value={trivyOptions.rpmOsVersion}
                                            onChange={(e) => setTrivyOptions((current) => ({ ...current, rpmOsVersion: e.target.value }))}
                                            placeholder="8"
                                            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                        <p className="mt-1 text-xs text-slate-500">RPM 단일 파일 취약점 매칭에 필요합니다.</p>
                                    </div>
                                </div>
                            )}

                            {[
                                ['offlineScan', '--offline-scan', '외부 네트워크 조회 없이 로컬 DB만 사용합니다.'],
                                ['skipDbUpdate', '--skip-db-update', '취약점 DB 업데이트를 건너뜁니다.'],
                                ['skipJavaDbUpdate', '--skip-java-db-update', 'Java DB 업데이트를 건너뜁니다.'],
                                ['ignoreUnfixed', '--ignore-unfixed', '수정 버전이 없는 항목은 제외합니다.'],
                            ].map(([key, label, description]) => (
                                <label key={key} className="flex cursor-pointer gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                                    <input
                                        type="checkbox"
                                        checked={Boolean(trivyOptions[key as keyof Required<TrivyScanOptions>])}
                                        onChange={(e) => setTrivyOptions((current) => ({ ...current, [key]: e.target.checked }))}
                                        className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900"
                                    />
                                    <span>
                                        <span className="block text-sm font-medium text-white">{label}</span>
                                        <span className="block text-xs text-slate-400">{description}</span>
                                    </span>
                                </label>
                            ))}

                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-300">Scanner</label>
                                <div className="space-y-2">
                                    {SCANNER_OPTIONS.map((scanner) => (
                                        <label key={scanner.value} className="flex items-center gap-2 text-sm text-slate-300">
                                            <input
                                                type="checkbox"
                                                checked={trivyOptions.scanners.includes(scanner.value)}
                                                onChange={() => toggleListOption('scanners', scanner.value)}
                                                className="h-4 w-4 rounded border-slate-600 bg-slate-900"
                                            />
                                            {scanner.label}
                                        </label>
                                    ))}
                                </div>
                            </div>

                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-300">심각도</label>
                                <div className="flex flex-wrap gap-2">
                                    {SEVERITY_OPTIONS.map((severity) => (
                                        <button
                                            type="button"
                                            key={severity}
                                            onClick={() => toggleListOption('severities', severity)}
                                            className={`rounded-full border px-3 py-1 text-xs font-medium ${
                                                trivyOptions.severities.includes(severity)
                                                    ? 'border-blue-400 bg-blue-500/20 text-blue-100'
                                                    : 'border-slate-700 bg-slate-950/40 text-slate-400'
                                            }`}
                                        >
                                            {severity}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-300">Timeout</label>
                                <input
                                    type="text"
                                    value={trivyOptions.timeout}
                                    onChange={(e) => setTrivyOptions((current) => ({ ...current, timeout: e.target.value }))}
                                    placeholder="10m"
                                    className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                                <p className="mt-1 text-xs text-slate-500">예: 30s, 10m, 1h</p>
                            </div>
                        </div>

                        <div className="mt-6 rounded-lg bg-slate-950/60 p-4 text-xs text-slate-400">
                            압축 파일은 서버 임시 폴더에만 해제되고, 스캔이 끝나면 원본과 해제된 파일이 함께 삭제됩니다.
                        </div>
                    </aside>
                </div>
            </div>
        </div>
    );
}
