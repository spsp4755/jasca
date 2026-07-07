'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Archive, ArrowLeft, CheckCircle, FileJson, Globe, Loader2, ShieldCheck, Upload, AlertCircle } from 'lucide-react';
import Link from 'next/link';
import { useCancelTrivyScan, useOrganizations, useProjects, useUploadScan, useZapScan } from '@/lib/api-hooks';
import type { CheckovScanOptions, TrivyScanOptions } from '@/lib/api-hooks';

type UploadMode = 'scan-target' | 'result-file';
type SourceType = 'TRIVY_JSON' | 'TRIVY_SARIF' | 'CHECKOV_JSON' | 'ZAP_JSON' | 'SARIF' | 'MANUAL';
type ScannerProvider = 'trivy' | 'checkov' | 'zap' | 'semgrep';

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

const CHECKOV_FRAMEWORK_OPTIONS = [
    { value: 'terraform', label: 'Terraform', description: '.tf, .tf.json IaC 설정', detail: 'Terraform 코드나 모듈 압축 파일을 올릴 때 선택합니다.' },
    { value: 'terraform_plan', label: 'Terraform Plan', description: 'terraform plan JSON 결과', detail: 'terraform show -json으로 만든 plan 결과를 검토할 때 사용합니다.' },
    { value: 'kubernetes', label: 'Kubernetes', description: 'Deployment, Pod, Service YAML', detail: '폐쇄망 k8s manifest의 권한, 보안 컨텍스트, 리소스 설정을 점검합니다.' },
    { value: 'helm', label: 'Helm', description: 'Helm Chart, values.yaml', detail: 'Chart.yaml, templates, values.yaml을 포함한 Helm chart 압축 파일에 적합합니다.' },
    { value: 'kustomize', label: 'Kustomize', description: 'kustomization.yaml 구성', detail: 'base/overlay 구조의 kustomize 디렉터리를 압축해서 올릴 때 사용합니다.' },
    { value: 'dockerfile', label: 'Dockerfile', description: 'Dockerfile 컨테이너 빌드 정책', detail: 'root 사용자, sudo, latest 태그, 위험한 패키지 설치 패턴 등을 확인합니다.' },
    { value: 'serverless', label: 'Serverless', description: 'serverless.yml 함수/권한 설정', detail: '사내에서 serverless.yml을 관리하는 경우에만 선택하면 됩니다.' },
    { value: 'arm', label: 'ARM Template', description: 'Azure ARM JSON 템플릿', detail: 'Azure를 사용하지 않는 폐쇄망이면 선택하지 않아도 됩니다.' },
    { value: 'bicep', label: 'Bicep', description: 'Azure .bicep 템플릿', detail: 'Azure Bicep 템플릿을 내부 IaC로 관리할 때만 사용합니다.' },
    { value: 'openapi', label: 'OpenAPI', description: 'openapi.yaml/json API 명세', detail: 'API 스펙의 인증, 보안 스키마, 노출 정보를 점검합니다.' },
    { value: 'github_actions', label: 'GitHub Actions', description: '.github/workflows/*.yml 정적 분석', detail: '폐쇄망 GitHub Enterprise를 쓰는 경우 워크플로 보안 설정을 확인합니다.' },
    { value: 'gitlab_ci', label: 'GitLab CI', description: '.gitlab-ci.yml 파이프라인 정책', detail: '사내 GitLab CI YAML의 권한, 스크립트, secret 사용 패턴을 점검합니다.' },
    { value: 'ansible', label: 'Ansible', description: 'playbook, role YAML 설정', detail: '서버 설정 자동화 playbook이나 role을 점검할 때 선택합니다.' },
] as const;

export default function NewScanPage() {
    const router = useRouter();
    const [uploadMode, setUploadMode] = useState<UploadMode>('scan-target');
    const [scannerProvider, setScannerProvider] = useState<ScannerProvider>('trivy');
    const [file, setFile] = useState<File | null>(null);
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');
    const [selectedOrgId, setSelectedOrgId] = useState<string>('');
    const [projectName, setProjectName] = useState<string>('');
    const [sourceType, setSourceType] = useState<SourceType>('TRIVY_JSON');
    const [zapTargetUrl, setZapTargetUrl] = useState('');
    const [zapScanMode, setZapScanMode] = useState<'baseline' | 'passive' | 'active'>('baseline');
    const [zapAuthType, setZapAuthType] = useState<'none' | 'cookie' | 'authorization'>('none');
    const [zapAuthValue, setZapAuthValue] = useState('');
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
    const [checkovOptions, setCheckovOptions] = useState<Required<CheckovScanOptions>>({
        frameworks: [],
        checks: [],
        skipChecks: [],
        quiet: true,
        timeout: '10m',
    });
    const [semgrepOptions, setSemgrepOptions] = useState<{ profile: 'all' | 'security' | 'custom-only'; languages: string[]; incremental: boolean }>({
        profile: 'all',
        languages: [],
        incremental: false,
    });

    const { data: projectsData } = useProjects();
    const { data: orgsData } = useOrganizations();
    const uploadMutation = useUploadScan();
    const zapScanMutation = useZapScan();
    const cancelScanMutation = useCancelTrivyScan();

    const projects = projectsData?.data || [];
    const organizations = orgsData || [];
    const isScanningTarget = uploadMode === 'scan-target';
    const isCheckovScan = isScanningTarget && scannerProvider === 'checkov';
    const isZapScan = isScanningTarget && scannerProvider === 'zap';
    const isSemgrepScan = isScanningTarget && scannerProvider === 'semgrep';
    const scanActionLabel = isZapScan ? 'ZAP 검사 실행' : isCheckovScan ? 'Checkov 검사 실행' : isSemgrepScan ? 'Semgrep 검사 실행' : 'Trivy 검사 실행';
    const scanProgressLabel = isZapScan ? 'ZAP 검사 중...' : isCheckovScan ? 'Checkov 검사 중...' : isSemgrepScan ? 'Semgrep 검사 중...' : 'Trivy 검사 중...';
    const missingZapRequiredInput = isZapScan && (!zapTargetUrl.trim() || (zapAuthType !== 'none' && !zapAuthValue.trim()));
    const isSubmitDisabled = uploadStatus === 'uploading' || uploadStatus === 'cancelling' || uploadStatus === 'success' || (isZapScan ? missingZapRequiredInput : !file);
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
            setSourceType(scannerProvider === 'checkov' ? 'CHECKOV_JSON' : scannerProvider === 'zap' ? 'ZAP_JSON' : scannerProvider === 'semgrep' ? 'SARIF' : 'TRIVY_JSON');
        }
    };

    const handleScannerChange = (scanner: ScannerProvider) => {
        setScannerProvider(scanner);
        if (scanner === 'zap') {
            setFile(null);
        }
        if (uploadMode === 'scan-target') {
            setSourceType(scanner === 'checkov' ? 'CHECKOV_JSON' : scanner === 'zap' ? 'ZAP_JSON' : scanner === 'semgrep' ? 'SARIF' : 'TRIVY_JSON');
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

    const toggleCheckovFramework = (value: string) => {
        setCheckovOptions((current) => ({
            ...current,
            frameworks: current.frameworks.includes(value)
                ? current.frameworks.filter((item) => item !== value)
                : [...current.frameworks, value],
        }));
    };

    const handleUpload = async () => {
        if (isZapScan) {
            if (!zapTargetUrl.trim()) {
                setErrorMessage('ZAP으로 검사할 URL을 입력해주세요.');
                return;
            }

            if (!selectedProjectId && !projectName.trim()) {
                setErrorMessage('프로젝트를 선택하거나 새 프로젝트 이름을 입력해주세요.');
                return;
            }

            if (zapAuthType !== 'none' && !zapAuthValue.trim()) {
                setErrorMessage('ZAP 인증 스캔을 사용하려면 Cookie 또는 Authorization 값을 입력해주세요.');
                return;
            }

            setUploadStatus('uploading');
            setErrorMessage('');
            cancelRequestedRef.current = false;
            const nextOperationId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            setScanOperationId(nextOperationId);

            try {
                const scanResult = await zapScanMutation.mutateAsync({
                    projectId: selectedProjectId || undefined,
                    targetUrl: zapTargetUrl.trim(),
                    scanMode: zapScanMode,
                    authentication: zapAuthType === 'none' ? { type: 'none' } : {
                        type: zapAuthType,
                        value: zapAuthValue.trim(),
                    },
                    projectName: !selectedProjectId ? projectName.trim() : undefined,
                    organizationId: selectedOrgId || undefined,
                    imageRef: zapTargetUrl.trim(),
                    scanOperationId: nextOperationId,
                });

                if (!isPageActiveRef.current) return;

                setUploadStatus('success');
                setScanOperationId('');
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
                    setErrorMessage('ZAP 스캔을 중지했습니다.');
                    return;
                }

                setUploadStatus('error');
                setErrorMessage(error.message || 'ZAP 스캔에 실패했습니다.');
            }
            return;
        }

        if (!file) {
            setErrorMessage('업로드할 파일을 선택해주세요.');
            return;
        }

        if (!selectedProjectId && !projectName.trim()) {
            setErrorMessage('프로젝트를 선택하거나 새 프로젝트 이름을 입력해주세요.');
            return;
        }

        if (isScanningTarget && scannerProvider === 'trivy' && trivyOptions.scanners.length === 0) {
            setErrorMessage('Trivy scanner를 최소 1개 이상 선택해주세요.');
            return;
        }

        if (isScanningTarget && scannerProvider === 'trivy' && trivyOptions.severities.length === 0) {
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
                scanner: isScanningTarget && scannerProvider !== 'zap' ? scannerProvider : undefined,
                trivyOptions: isScanningTarget && scannerProvider === 'trivy' ? trivyOptions : undefined,
                checkovOptions: isScanningTarget && scannerProvider === 'checkov' ? checkovOptions : undefined,
                semgrepOptions: isScanningTarget && scannerProvider === 'semgrep'
                    ? { ...semgrepOptions, incremental: semgrepOptions.incremental && !!selectedProjectId }
                    : undefined,
                scanOperationId: nextOperationId || undefined,
                signal: uploadAbortController.signal,
                metadata: {
                    sourceType: isScanningTarget
                        ? (scannerProvider === 'checkov' ? 'CHECKOV_JSON' : scannerProvider === 'semgrep' ? 'SARIF' : 'TRIVY_JSON')
                        : sourceType,
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

                        {isScanningTarget && (
                            <div className="mb-6 rounded-xl border border-slate-800 bg-slate-950/40 p-4">
                                <label className="mb-3 block text-sm font-medium text-slate-300">실행 스캐너</label>
                                <div className="grid gap-3 sm:grid-cols-2">
                                    {[
                                        { value: 'trivy' as const, label: 'Trivy', description: '패키지 취약점, 라이선스, Secret, Misconfig 검사' },
                                        { value: 'checkov' as const, label: 'Checkov', description: 'IaC, Kubernetes, Dockerfile, CI 설정 오류 검사' },
                                        { value: 'zap' as const, label: 'ZAP', description: '웹 URL 대상 DAST Baseline/Passive 검사' },
                                        { value: 'semgrep' as const, label: 'Semgrep (SAST)', description: '소스코드 취약 패턴 검사 — 소스 zip/tar 업로드' },
                                    ].map((scanner) => (
                                        <button
                                            key={scanner.value}
                                            type="button"
                                            onClick={() => handleScannerChange(scanner.value)}
                                            className={`rounded-lg border p-3 text-left transition ${
                                                scannerProvider === scanner.value
                                                    ? 'border-cyan-400 bg-cyan-500/10 text-white'
                                                    : 'border-slate-700 text-slate-300 hover:border-slate-500'
                                            }`}
                                        >
                                            <div className="font-semibold">{scanner.label}</div>
                                            <div className="mt-1 text-xs text-slate-400">{scanner.description}</div>
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}

                        {isZapScan && (
                            <div className="mb-6 rounded-xl border border-orange-500/30 bg-orange-500/10 p-4">
                                <div className="mb-3 flex items-center gap-2 text-orange-100">
                                    <Globe className="h-5 w-5" />
                                    <span className="font-semibold">ZAP 웹 URL 스캔</span>
                                </div>
                                <label className="mb-2 block text-sm font-medium text-orange-100">검사 대상 URL</label>
                                <input
                                    type="url"
                                    value={zapTargetUrl}
                                    onChange={(e) => setZapTargetUrl(e.target.value)}
                                    placeholder="https://app.internal"
                                    className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                />
                                <div className="mt-4">
                                    <label className="mb-2 block text-sm font-medium text-orange-100">스캔 모드</label>
                                    <select
                                        value={zapScanMode}
                                        onChange={(e) => setZapScanMode(e.target.value as 'baseline' | 'passive' | 'active')}
                                        className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                                    >
                                        <option value="baseline">Baseline - Spider 실행 후 Passive Alert 수집</option>
                                        <option value="passive">Passive - Baseline과 동일한 안전 모드</option>
                                        <option value="active">Active - 관리자 허용 시에만 사용</option>
                                    </select>
                                </div>
                                <p className="mt-3 text-xs text-orange-100/80">
                                    관리자 설정의 허용 대상 패턴에 포함된 URL만 스캔할 수 있습니다.
                                </p>
                                <div className="mt-5 rounded-lg border border-orange-200/30 bg-slate-950/30 p-3">
                                    <label className="mb-2 block text-sm font-medium text-orange-100">인증 방식</label>
                                    <select
                                        value={zapAuthType}
                                        onChange={(e) => {
                                            setZapAuthType(e.target.value as 'none' | 'cookie' | 'authorization');
                                            setZapAuthValue('');
                                        }}
                                        className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                                    >
                                        <option value="none">인증 없음 - 로그인 전 공개 화면만 스캔</option>
                                        <option value="cookie">Cookie - 로그인 세션 쿠키를 스캔 중에만 사용</option>
                                        <option value="authorization">Authorization Header - Bearer/API 토큰 사용</option>
                                    </select>
                                    {zapAuthType !== 'none' && (
                                        <div className="mt-3">
                                            <label className="mb-2 block text-sm font-medium text-orange-100">
                                                {zapAuthType === 'cookie' ? 'Cookie 헤더 값' : 'Authorization 헤더 값'}
                                            </label>
                                            <textarea
                                                value={zapAuthValue}
                                                onChange={(e) => setZapAuthValue(e.target.value)}
                                                rows={3}
                                                placeholder={zapAuthType === 'cookie' ? 'SESSION=...; KEYCLOAK_IDENTITY=...' : 'Bearer eyJ...'}
                                                className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                            />
                                            <p className="mt-2 text-xs text-orange-100/80">
                                                입력값은 ZAP 스캔 중 요청 헤더로만 사용하고, 스캔 결과에는 저장하지 않습니다. 테스트 전용 계정의 세션을 권장합니다.
                                            </p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {!isZapScan && (
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
                        )}

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
                                    <option value="CHECKOV_JSON">Checkov JSON</option>
                                    <option value="SARIF">SARIF (외부 SAST 결과 — Semgrep, CodeQL, Checkmarx 등)</option>
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
                            disabled={isSubmitDisabled}
                            className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 py-3 font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-700"
                        >
                            {uploadStatus === 'uploading' ? (
                                <>
                                    <Loader2 className="h-5 w-5 animate-spin" />
                                    {isScanningTarget ? scanProgressLabel : '업로드 중...'}
                                </>
                            ) : uploadStatus === 'success' ? (
                                <>
                                    <CheckCircle className="h-5 w-5" />
                                    완료
                                </>
                            ) : (
                                <>
                                    <Upload className="h-5 w-5" />
                                    {isScanningTarget ? scanActionLabel : '결과 업로드'}
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
                        {isZapScan && (
                            <div className="mb-6 rounded-xl border border-orange-500/30 bg-orange-500/10 p-4">
                                <h2 className="text-lg font-semibold text-white">ZAP 실행 옵션</h2>
                                <p className="mt-2 text-sm text-slate-300">
                                    ZAP은 웹 애플리케이션 URL을 대상으로 DAST 검사를 수행합니다. 폐쇄망에서는 관리자 설정의 ZAP 서버 URL과 허용 대상 패턴이 먼저 구성되어야 합니다.
                                </p>
                                <div className="mt-4 space-y-3 text-sm text-slate-300">
                                    <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                                        <p className="font-medium text-white">Baseline</p>
                                        <p className="mt-1 text-slate-400">대상을 spider로 탐색하고 passive alert를 수집하는 운영 기본 모드입니다.</p>
                                    </div>
                                    <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                                        <p className="font-medium text-white">Passive</p>
                                        <p className="mt-1 text-slate-400">현재 1차 구현에서는 Baseline과 동일한 안전 스캔 흐름으로 처리됩니다.</p>
                                    </div>
                                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
                                        <p className="font-medium text-red-100">Active</p>
                                        <p className="mt-1 text-red-100/80">대상 서비스에 부하를 줄 수 있어 관리자 설정에서 허용된 경우에만 실행됩니다.</p>
                                    </div>
                                </div>
                            </div>
                        )}
                        {isCheckovScan && (
                            <div className="checkov-mode-panel mb-6 rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-4">
                                <h2 className="text-lg font-semibold text-white">Checkov 실행 옵션</h2>
                                <p className="mt-2 text-sm text-slate-300">
                                    폐쇄망 기본값은 외부 모듈 다운로드 비활성화입니다. 필요한 프레임워크만 선택하면 스캔 시간을 줄일 수 있습니다.
                                </p>

                                <div className="mt-5 space-y-4">
                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">Framework</label>
                                        <div className="grid grid-cols-2 gap-2">
                                            {CHECKOV_FRAMEWORK_OPTIONS.map((framework) => (
                                                <label
                                                    key={framework.value}
                                                    className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-300"
                                                >
                                                    <input
                                                        type="checkbox"
                                                        checked={checkovOptions.frameworks.includes(framework.value)}
                                                        onChange={() => toggleCheckovFramework(framework.value)}
                                                        className="mt-0.5 h-4 w-4 rounded border-slate-600 bg-slate-900"
                                                    />
                                                    <span>
                                                        <span className="block font-medium text-slate-100">{framework.label}</span>
                                                        <span className="mt-0.5 block leading-4 text-slate-500">{framework.description}</span>
                                                        <span className="mt-1 block leading-4 text-cyan-100/80">{framework.detail}</span>
                                                    </span>
                                                </label>
                                            ))}
                                        </div>
                                        <p className="mt-2 text-xs text-slate-500">선택하지 않으면 Checkov가 지원 프레임워크를 자동 감지합니다.</p>
                                    </div>

                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">실행할 Check ID</label>
                                        <textarea
                                            value={checkovOptions.checks.join(',')}
                                            onChange={(e) => setCheckovOptions((current) => ({ ...current, checks: e.target.value.split(/[,\n]/).map((item) => item.trim()).filter(Boolean) }))}
                                            placeholder="예: CKV_AWS_20, CKV_K8S_8"
                                            className="min-h-[72px] w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                        <p className="mt-1 text-xs text-slate-500">비워두면 전체 정책을 실행합니다.</p>
                                    </div>

                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">제외할 Check ID</label>
                                        <textarea
                                            value={checkovOptions.skipChecks.join(',')}
                                            onChange={(e) => setCheckovOptions((current) => ({ ...current, skipChecks: e.target.value.split(/[,\n]/).map((item) => item.trim()).filter(Boolean) }))}
                                            placeholder="예: CKV_AWS_999"
                                            className="min-h-[72px] w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                    </div>

                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">Timeout</label>
                                        <input
                                            type="text"
                                            value={checkovOptions.timeout}
                                            onChange={(e) => setCheckovOptions((current) => ({ ...current, timeout: e.target.value }))}
                                            placeholder="10m"
                                            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                        <p className="mt-1 text-xs text-slate-500">예: 30s, 10m, 1h</p>
                                    </div>
                                </div>
                            </div>
                        )}
                        {isSemgrepScan && (
                            <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-4">
                                <div>
                                    <h2 className="text-lg font-semibold text-white">Semgrep 실행 옵션</h2>
                                    <p className="mt-2 text-sm text-slate-400">
                                        소스코드(.zip, .tar, .tar.gz)를 업로드하면 서버에 내장된 Semgrep 룰로 소스코드
                                        취약 패턴(SAST)을 검사합니다. 폐쇄망에서 외부 연결 없이 동작합니다.
                                    </p>
                                </div>
                                <div>
                                    <label className="mb-2 block text-sm font-medium text-slate-300">스캔 프로파일</label>
                                    <div className="space-y-2">
                                        {([
                                            { value: 'all', label: '전체 룰', description: '번들 룰 전체 + 커스텀 룰 (가장 넓은 커버리지)' },
                                            { value: 'security', label: '보안 룰만', description: 'security 카테고리 룰만 적용 (노이즈·시간 감소)' },
                                            { value: 'custom-only', label: '커스텀 룰만', description: '관리자가 등록한 조직 커스텀 룰만 적용' },
                                        ] as const).map((p) => (
                                            <label key={p.value} className="flex items-start gap-2 text-sm text-slate-300 cursor-pointer">
                                                <input
                                                    type="radio"
                                                    name="semgrepProfile"
                                                    checked={semgrepOptions.profile === p.value}
                                                    onChange={() => setSemgrepOptions((prev) => ({ ...prev, profile: p.value }))}
                                                    className="mt-0.5"
                                                />
                                                <span>
                                                    <span className="font-medium text-white">{p.label}</span>
                                                    <span className="ml-2 text-xs text-slate-400">{p.description}</span>
                                                </span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                                <div>
                                    <label className={`flex items-start gap-2 text-sm ${selectedProjectId ? 'text-slate-300 cursor-pointer' : 'text-slate-500'}`}>
                                        <input
                                            type="checkbox"
                                            disabled={!selectedProjectId}
                                            checked={semgrepOptions.incremental && !!selectedProjectId}
                                            onChange={(e) => setSemgrepOptions((prev) => ({ ...prev, incremental: e.target.checked }))}
                                            className="mt-0.5"
                                        />
                                        <span>
                                            <span className="font-medium text-white">증분 스캔</span>
                                            <span className="ml-2 text-xs text-slate-400">
                                                {selectedProjectId
                                                    ? '직전 스캔 대비 변경된 파일만 검사하고 결과를 병합합니다 (빠름)'
                                                    : '기존 프로젝트를 선택하면 사용할 수 있습니다'}
                                            </span>
                                        </span>
                                    </label>
                                </div>
                                {semgrepOptions.profile !== 'custom-only' && (
                                    <div>
                                        <label className="mb-2 block text-sm font-medium text-slate-300">
                                            언어 제한 <span className="font-normal text-slate-500">(선택 없음 = 전체 언어)</span>
                                        </label>
                                        <div className="flex flex-wrap gap-2">
                                            {['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'c', 'csharp', 'kotlin', 'rust', 'terraform', 'dockerfile'].map((lang) => {
                                                const checked = semgrepOptions.languages.includes(lang);
                                                return (
                                                    <button
                                                        key={lang}
                                                        type="button"
                                                        onClick={() => setSemgrepOptions((prev) => ({
                                                            ...prev,
                                                            languages: prev.languages.includes(lang)
                                                                ? prev.languages.filter((l) => l !== lang)
                                                                : [...prev.languages, lang],
                                                        }))}
                                                        className={`px-2.5 py-1 rounded-full text-xs transition ${
                                                            checked
                                                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400'
                                                                : 'border border-slate-700 text-slate-400 hover:border-slate-500'
                                                        }`}
                                                    >
                                                        {lang}
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                        {!isCheckovScan && !isZapScan && !isSemgrepScan && (
                            <>
                                <h2 className="text-lg font-semibold text-white">Trivy 실행 옵션</h2>
                                <p className="mt-2 text-sm text-slate-400">
                                    폐쇄망 기본값은 DB 다운로드를 시도하지 않도록 설정되어 있습니다.
                                </p>

                                <div className={`mt-5 space-y-4 ${!isScanningTarget ? 'hidden pointer-events-none opacity-50' : ''}`}>
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
                            </>
                        )}

                        <div className="mt-6 rounded-lg bg-slate-950/60 p-4 text-xs text-slate-400">
                            압축 파일은 서버 임시 폴더에만 해제되고, 스캔이 끝나면 원본과 해제된 파일이 함께 삭제됩니다.
                        </div>
                    </aside>
                </div>
            </div>
        </div>
    );
}
