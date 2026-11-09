import { useEffect, useRef, useState, type DragEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import Tabs from "../components/Tabs";
import Field from "../components/Field";
import Button from "../components/Button";
import StatusBadge from "../components/StatusBadge";
import { useToast } from "../components/Toast";
import { API_BASE, ApiError, api, loginUrl } from "../api/client";
import { isAdmin, useApi, useMe } from "../api/hooks";
import CiSnippet from "../components/CiSnippet";
import type { Project, Scan, ScanJobCreated } from "../api/types";
import { Panel } from "./admin/parts";
import "../styles/t17.css";

const DONE = ["done", "failed", "canceled"];

/** multipart upload through XHR (fetch has no upload progress). */
function uploadJob(key: string, form: FormData, onProgress: (pct: number) => void, abort: { current: XMLHttpRequest | null }) {
  return new Promise<ScanJobCreated>((resolve, reject) => {
    const x = new XMLHttpRequest();
    abort.current = x;
    x.open("POST", `${API_BASE}/projects/${encodeURIComponent(key)}/scan-jobs`);
    x.setRequestHeader("Accept", "application/json");
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    x.onerror = () => reject(new ApiError(0, "network", "서버에 연결하지 못했습니다. 네트워크를 확인하세요."));
    x.onabort = () => reject(new ApiError(0, "aborted", "업로드를 취소했습니다."));
    x.onload = () => {
      let body: { error?: string; message?: string } & Partial<ScanJobCreated> = {};
      try { body = JSON.parse(x.responseText); } catch { /* proxy error page */ }
      if (x.status === 401) location.assign(loginUrl());
      if (x.status >= 200 && x.status < 300 && body.scan_id) resolve({ scan_id: body.scan_id });
      else reject(new ApiError(x.status, body.error || `http_${x.status}`, body.message || (x.status === 413 ? "파일이 너무 큽니다." : `업로드하지 못했습니다. (${x.status})`)));
    };
    x.send(form);
  });
}

function ScanProgress({ id }: { id: number }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useApi<Scan>(`/scans/${id}`, { refetchInterval: (query) => (query.state.data && DONE.includes(query.state.data.status) ? false : 2000), staleTime: 0 });
  const cancel = useMutation<void, ApiError>({
    mutationFn: () => api.post<void>(`/scans/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: [`/scans/${id}`] }),
    onError: (e) => toast(e.message, "error"),
  });
  const s = q.data;
  const active = s && !DONE.includes(s.status);
  return (
    <div className="alert alert-info" role="status" style={{ alignItems: "center" }}>
      <div className="stack" style={{ gap: 6, flex: 1 }}>
        <div className="row-gap"><strong>스캔 #{id}</strong>{s ? <StatusBadge status={s.status} /> : <span className="muted">확인 중…</span>}
          {active && <span className="muted">2초마다 상태를 확인합니다.</span>}</div>
        {s?.status === "failed" && <span>{s.error || "스캔에 실패했습니다."}</span>}
        {s?.status === "done" && <span>{s.policy ? (s.policy.passed ? "정책을 통과했습니다." : `정책 위반: ${s.policy.reasons.join(", ")}`) : "스캔이 끝났습니다."}</span>}
        {q.error && <span>{q.error.message}</span>}
      </div>
      {active && <Button size="sm" variant="danger" loading={cancel.isPending} onClick={() => cancel.mutate()}>취소</Button>}
      {s?.status === "done" && <Link className="btn btn-secondary btn-sm" to={`/scans/${id}`}>결과 보기</Link>}
    </div>
  );
}

function UploadTab({ projects }: { projects: Project[] }) {
  const toast = useToast();
  const [key, setKey] = useState("");
  const [target, setTarget] = useState("");
  const [kind, setKind] = useState<"fs" | "image">("fs");
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [pct, setPct] = useState<number | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const xhr = useRef<XMLHttpRequest | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const uploading = pct !== null;
  useEffect(() => () => xhr.current?.abort(), []);
  const drop = (e: DragEvent) => { e.preventDefault(); setOver(false); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]); };
  const submit = async () => {
    if (!file) return;
    const fd = new FormData();
    fd.set("target", target.trim()); fd.set("kind", kind); fd.set("file", file);
    setScanId(null); setPct(0);
    try { setScanId((await uploadJob(key, fd, setPct, xhr)).scan_id); }
    catch (e) { if ((e as ApiError).code !== "aborted") toast((e as ApiError).message, "error"); }
    finally { setPct(null); xhr.current = null; }
  };
  const writable = projects.filter((p) => p.my_role !== "viewer");
  return (
    <Panel title="서버에서 스캔" meta="파일을 올리면 서버의 Trivy가 검사합니다">
      <form className="stack" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        <Field label="프로젝트" required>
          <select className="input" value={key} onChange={(e) => setKey(e.target.value)} required>
            <option value="">선택하세요</option>
            {writable.map((p) => <option key={p.key} value={p.key}>{p.name} ({p.key})</option>)}
          </select>
        </Field>
        <Field label="대상 이름" required hint="결과를 묶는 이름입니다. 예: web-app, registry.example.internal/team/app:1.0">
          <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} required maxLength={200} />
        </Field>
        <Field label="종류" hint="fs: 소스·패키지 디렉터리를 압축한 파일 / image: docker save 로 만든 tar">
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value as "fs" | "image")}>
            <option value="fs">fs (압축 파일)</option><option value="image">image (이미지 tar)</option>
          </select>
        </Field>
        <div className={`dropzone${over ? " over" : ""}`} role="button" tabIndex={0} aria-label="파일 선택"
          onClick={() => input.current?.click()} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={drop}>
          {file ? <><strong>{file.name}</strong> <span className="muted">({(file.size / 1048576).toFixed(1)} MB)</span></> : "여기에 파일을 끌어다 놓거나 눌러서 선택하세요."}
          <input ref={input} type="file" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </div>
        {uploading && (
          <div className="row-gap" role="status">
            <div className="progress" style={{ flex: 1 }} role="progressbar" aria-valuenow={pct ?? 0} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${pct}%` }} /></div>
            <span className="num">{pct}%</span>
            <Button size="sm" onClick={() => xhr.current?.abort()}>업로드 취소</Button>
          </div>
        )}
        <div className="row-gap"><Button type="submit" variant="primary" disabled={!key || !target.trim() || !file || uploading}>스캔 시작</Button></div>
      </form>
      {scanId !== null && <div style={{ marginTop: 14 }}><ScanProgress id={scanId} /></div>}
    </Panel>
  );
}

/** Project picker in front of the shared CI snippet (components/CiSnippet). */
function CiTab({ projects }: { projects: Project[] }) {
  const [key, setKey] = useState("");
  return (
    <Panel title="CI 연동" meta="Trivy JSON 보고서를 CI에서 직접 올립니다">
      <div className="stack">
        <select className="input" style={{ width: 280 }} aria-label="프로젝트" value={key} onChange={(e) => setKey(e.target.value)}>
          <option value="">프로젝트 선택</option>{projects.map((p) => <option key={p.key} value={p.key}>{p.name} ({p.key})</option>)}
        </select>
        <CiSnippet projectKey={key || "<프로젝트-키>"} />
        <p className="muted">같은 보고서를 다시 올리면 <code>duplicate: true</code>로 응답하고 새 스캔을 만들지 않습니다.</p>
      </div>
    </Panel>
  );
}

function HarborTab() {
  const { data: me } = useMe();
  return (
    <Panel title="Harbor 연동">
      <div className="stack">
        <p>Harbor에 이미지를 푸시하면 Harbor가 웹훅으로 JASCA에 알리고, JASCA가 Harbor의 Trivy 보고서를 가져와 자동으로 등록합니다. 사용자가 따로 올릴 필요가 없습니다.</p>
        <ol className="steps" style={{ margin: "0 0 0 18px" }}>
          <li>관리자가 Harbor 연결(주소, 로봇 계정)을 등록하고 웹훅 주소와 비밀값을 Harbor에 설정합니다.</li>
          <li>Harbor 프로젝트와 저장소 패턴을 JASCA 프로젝트에 매핑합니다.</li>
          <li>매핑되지 않은 이미지는 관리자 화면의 &quot;매핑 안 된 이미지&quot; 목록에 쌓입니다.</li>
        </ol>
        {isAdmin(me) ? <div><Link className="btn btn-secondary btn-sm" to="/admin/harbor">Harbor 관리로 이동</Link></div>
          : <p className="muted">연결 설정은 관리자만 할 수 있습니다. 필요하면 관리자에게 요청하세요.</p>}
      </div>
    </Panel>
  );
}

export default function ScanNew() {
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") ?? "upload";
  const projects = useApi<Project[]>("/projects");
  const list = projects.data ?? [];
  return (
    <>
      <PageHeader title="스캔하기" description="파일을 올려 서버에서 검사하거나, CI·Harbor로 자동 등록하세요." />
      <div className="page-narrow">
        <Tabs label="스캔 방법" value={tab} onChange={(t) => setSp({ tab: t }, { replace: true })}
          tabs={[{ id: "upload", label: "파일 업로드" }, { id: "ci", label: "CI 연동" }, { id: "harbor", label: "Harbor" }]} />
        {projects.error && <div className="alert alert-danger" role="alert">{projects.error.message}</div>}
        <div role="tabpanel" id={`tabpanel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === "ci" ? <CiTab projects={list} /> : tab === "harbor" ? <HarborTab /> : <UploadTab projects={list} />}
        </div>
      </div>
    </>
  );
}
