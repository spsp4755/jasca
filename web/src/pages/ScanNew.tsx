import { useEffect, useRef, useState, type DragEvent } from "react";
import { Link, useBlocker, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import Tabs from "../components/Tabs";
import Field from "../components/Field";
import Button from "../components/Button";
import Icon from "../components/Icon";
import { useToast } from "../components/Toast";
import { API_BASE, ApiError, api, loginUrl } from "../api/client";
import { isAdmin, useApi, useAuthConfig, useMe, useUnloadGuard } from "../api/hooks";
import { SEVERITIES, type Counts, type Project, type ScanDetail, type ScanJobCreated, type Target } from "../api/types";
import { SEVERITY_LABEL, fmtNumber } from "../lib/format";
import { Panel } from "./admin/parts";
import { KEY_RE, suggestKey } from "./Projects";
import "../styles/t17.css";

const DONE = ["done", "failed", "canceled"];
const NEW = "__new__";
const LAST_PROJECT = "jasca.scan.project";
type Kind = "fs" | "image";
const KIND_TEXT: Record<Kind, [string, string]> = {
  fs: ["소스 코드·패키지", "프로젝트 폴더를 압축한 zip, tar, tar.gz"],
  image: ["컨테이너 이미지", "docker save 또는 podman save로 만든 tar"],
};

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

// A first tar entry that only a docker/podman save or OCI layout archive has. index.json and manifest.json are not
// among them: web apps have those too. A wrong guess either way is caught by the server, which says what to pick.
const IMAGE_ENTRY = /^(\.\/)?(blobs\/|oci-layout$|repositories$|[0-9a-f]{64}(\/|\.json$|\.tar$))/;

/** Guesses what the file is from its first tar header, so the user does not have to know "fs" from "image". */
async function sniffKind(file: File): Promise<Kind> {
  const byName: Kind = /\.tar$/i.test(file.name) ? "image" : "fs";
  try {
    let head = new Uint8Array(await file.slice(0, 512).arrayBuffer());
    if (head[0] === 0x50 && head[1] === 0x4b) return "fs"; // zip
    if (head[0] === 0x1f && head[1] === 0x8b) { // gzip: inflate only the first block
      const r = file.slice(0, 1 << 16).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
      const { value } = await r.read();
      r.cancel().catch(() => {});
      if (!value || value.length < 512) return byName;
      head = value.slice(0, 512);
    }
    if (new TextDecoder().decode(head.slice(257, 262)) !== "ustar") return byName;
    return IMAGE_ENTRY.test(new TextDecoder().decode(head.slice(0, 100)).replace(/\0[\s\S]*$/, "")) ? "image" : "fs";
  } catch { return byName; }
}

const baseName = (file: string) => file.replace(/\.(tar\.gz|tgz|tar|zip)$/i, "").slice(0, 200);
/** JASCA_MAX_SCAN_UPLOAD_MB as people say it: 2048 → "2GB", 500 → "500MB". */
const fmtLimit = (mb: number) => (mb >= 1024 ? `${+(mb / 1024).toFixed(1)}GB` : `${mb}MB`);
const fmtSize = (n: number) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GB` : n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);
const clock = (sec: number) => `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, "0")}`;

/** Seconds since `since` while `on`. */
function useElapsed(on: boolean, since: number) {
  const [, tick] = useState(0);
  useEffect(() => { if (!on) return; const t = setInterval(() => tick((n) => n + 1), 1000); return () => clearInterval(t); }, [on]);
  return Math.max(0, Math.floor((Date.now() - since) / 1000));
}

/** startedAt: when the upload finished and the wait for the server began (the upload has its own percentage). */
type Run = { file: string; target: string; projectKey: string; projectName: string; pct: number; scanId: number | null; startedAt: number; error?: string };

/** Upload → scan → result, in place of the form while a run is going. */
function ScanRun({ run, onCancelUpload, onAgain, onEdit }: { run: Run; onCancelUpload: () => void; onAgain: () => void; onEdit: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useApi<ScanDetail>(run.scanId ? `/scans/${run.scanId}` : null, { refetchInterval: (query) => (query.state.data && DONE.includes(query.state.data.status) ? false : 2000), staleTime: 0 });
  const cancel = useMutation<void, ApiError>({
    mutationFn: () => api.post<void>(`/scans/${run.scanId}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: [`/scans/${run.scanId}`] }),
    onError: (e) => toast(e.message, "error"),
  });
  const s = q.data;
  const uploading = run.scanId === null && !run.error;
  const finished = !!s && DONE.includes(s.status);
  const elapsed = useElapsed(!finished && !run.error, run.startedAt);
  useEffect(() => { if (s?.status === "done") qc.invalidateQueries({ queryKey: ["/projects"] }); }, [s?.status, qc]);
  const canceled = s?.status === "canceled"; // the user's own choice, not a failure
  const failed = run.error || (s?.status === "failed" ? s.error || "스캔에 실패했습니다." : q.error?.message);
  const warnings = s?.summary.warnings ?? [];
  // the result replaces the progress steps: keyboard and screen reader users land on it
  const head = useRef<HTMLHeadingElement>(null);
  const settled = finished || !!failed;
  useEffect(() => { if (settled) head.current?.focus(); }, [settled]);
  const step = uploading ? 0 : finished ? 2 : 1;
  const steps: [string, string][] = [
    ["파일 올리기", uploading ? `${run.pct}%` : run.error ? "" : "완료"],
    ["서버에서 검사", step < 1 ? "" : finished ? "완료" : s?.status === "running" ? `검사 중 · ${clock(elapsed)}` : `순서를 기다리는 중 · ${clock(elapsed)}`],
    ["결과", ""],
  ];
  const total = s ? SEVERITIES.reduce((n, sev) => n + (s.summary[sev.toLowerCase() as keyof Counts] ?? 0), 0) : 0;
  return (
    <section className="panel scan-run" aria-labelledby="h-run">
      <div className="panel-head">
        <h2 id="h-run" ref={head} tabIndex={-1}>{run.target}</h2>
        <span className="panel-meta">{run.file} · {run.projectName} 프로젝트에 저장</span>
      </div>
      <div className="panel-body stack">
        {!failed && !canceled && s?.status !== "done" && (
          <>
            <ol className="scan-steps" role="status" aria-label="스캔 진행 상황">
              {steps.map(([label, note], i) => (
                <li key={label} className={i < step ? "is-done" : i === step ? "is-active" : undefined} aria-current={i === step ? "step" : undefined}>
                  <span className="scan-step-mark" aria-hidden="true">{i < step ? <Icon name="check" size={14} /> : i === step ? <span className="spinner" /> : i + 1}</span>
                  <span className="scan-step-label">{label}</span>
                  {note && <span className="scan-step-note num">{note}</span>}
                </li>
              ))}
            </ol>
            {uploading && <div className="progress" role="progressbar" aria-label="파일 업로드 진행률" aria-valuenow={run.pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${run.pct}%` }} /></div>}
            <p className="muted" style={{ margin: 0 }}>{uploading ? "올리는 동안 이 화면을 닫지 마세요." : "화면을 떠나도 검사는 계속됩니다. 결과는 프로젝트의 스캔 목록에서 다시 볼 수 있습니다."}</p>
            <div className="row-gap">
              {uploading ? <Button onClick={onCancelUpload}>업로드 취소</Button>
                : <Button variant="danger" loading={cancel.isPending} onClick={() => cancel.mutate()}>스캔 취소</Button>}
            </div>
          </>
        )}
        {failed && (
          <>
            <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" /><span><b>스캔하지 못했습니다.</b> {failed}</span></div>
            <div className="row-gap"><Button variant="primary" onClick={onEdit}>고쳐서 다시 시도</Button>{run.scanId && <Link className="btn btn-secondary" to={`/scans/${run.scanId}`}>스캔 기록 보기</Link>}</div>
          </>
        )}
        {canceled && (
          <>
            <div className="alert alert-info" role="status" style={{ margin: 0 }}><Icon name="info" /><span>스캔을 취소했습니다. 저장된 결과는 없습니다.</span></div>
            <div className="row-gap"><Button variant="primary" onClick={onEdit}>다시 스캔</Button><Link className="btn btn-secondary" to={`/scans/${run.scanId}`}>스캔 기록 보기</Link></div>
          </>
        )}
        {s?.status === "done" && (
          <div role="status" className="stack">
            <p className="scan-verdict">
              <Icon name={total || warnings.length ? "alert" : "shieldCheck"} size={20} />
              <span><b>검사를 마쳤습니다.</b> {total ? <>열린 결과가 <b className="num">{fmtNumber(total)}</b>건 있습니다.</>
                : warnings.length ? "검사하지 못한 것이 있어 '결과 없음'으로 볼 수 없습니다." : "발견된 결과가 없습니다."}
                {!!s.summary.packages && <> 패키지 <b className="num">{fmtNumber(s.summary.packages)}</b>개를 검사했습니다.</>}
                {s.diff.previous_scan_id != null && <> 이전 스캔보다 새로 발견 <b className="num">{fmtNumber(s.diff.new)}</b>건, 사라짐 <b className="num">{fmtNumber(s.diff.fixed)}</b>건입니다.</>}</span>
            </p>
            {warnings.map((w) => <div key={w} className="alert alert-warn" style={{ margin: 0 }}><Icon name="alert" /><span>{w}</span></div>)}
            <ul className="sev-tiles scan-tiles">
              {SEVERITIES.map((sev) => {
                const n = s.summary[sev.toLowerCase() as keyof Counts] ?? 0;
                return (
                  <li key={sev} className={n === 0 ? "is-zero" : undefined}>
                    <span className="risk-label"><span className={`sev-dot dot-${sev.toLowerCase()}`} aria-hidden="true" />{SEVERITY_LABEL[sev]}</span>
                    <span className="risk-n num">{fmtNumber(n)}</span>
                  </li>
                );
              })}
            </ul>
            {s.policy && (s.policy.passed
              ? <p className="scan-policy scan-policy-pass"><Icon name="shieldCheck" />정책 통과: 프로젝트 정책의 기준을 넘는 결과가 없습니다.</p>
              : <p className="scan-policy scan-policy-fail" role="alert"><Icon name="alert" />정책 실패: {(s.policy.reasons?.length ? s.policy.reasons : [s.policy.error || "사유가 기록되지 않았습니다."]).join(", ")}</p>)}
            <div className="row-gap">
              <Link className="btn btn-primary" to={`/scans/${s.id}`}>결과 자세히 보기</Link>
              <Button onClick={onAgain}>다른 파일 스캔</Button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function UploadTab({ projects, loaded }: { projects: Project[]; loaded: boolean }) {
  const qc = useQueryClient();
  const [sp] = useSearchParams();
  const writable = projects.filter((p) => p.my_role !== "viewer");
  const [key, setKey] = useState("");
  const [newName, setNewName] = useState("");
  const [newKey, setNewKey] = useState("");
  const [keyEdited, setKeyEdited] = useState(false);
  const [target, setTarget] = useState("");
  const [targetEdited, setTargetEdited] = useState(false);
  const [kind, setKind] = useState<Kind>("fs");
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [tried, setTried] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [run, setRun] = useState<Run | null>(null);
  const [editing, setEditing] = useState(true);
  const xhr = useRef<XMLHttpRequest | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const [fileErr, setFileErr] = useState("");
  const cfg = useAuthConfig();
  const maxMB = cfg.data?.max_scan_upload_mb;
  const noDb = cfg.data?.trivy_db_ready === false;
  useEffect(() => { if (noDb) void cfg.refetch(); }, []); // eslint-disable-line react-hooks/exhaustive-deps -- cached for the session: the admin may have uploaded the DB since
  useEffect(() => () => xhr.current?.abort(), []);
  // leaving now would throw the upload away: the browser asks on reload/close, the router on a move inside the app
  const uploading = !!run && !editing && run.scanId === null && !run.error;
  useUnloadGuard(uploading);
  const blocker = useBlocker(uploading);
  useEffect(() => {
    if (blocker.state !== "blocked") return;
    if (confirm("파일을 올리는 중입니다. 이 화면을 떠나면 업로드가 취소됩니다. 떠날까요?")) blocker.proceed(); else blocker.reset();
  }, [blocker]);

  // First choice once the list is in: ?project=, then the last one used, then the only one; none at all starts a new project.
  useEffect(() => {
    if (!loaded || key) return;
    let last = "";
    try { last = localStorage.getItem(LAST_PROJECT) ?? ""; } catch { /* storage blocked */ }
    const has = (k: string | null) => !!k && writable.some((p) => p.key === k);
    const want = sp.get("project");
    setKey(has(want) ? want! : has(last) ? last : writable.length === 1 ? writable[0].key : writable.length === 0 ? NEW : "");
  }, [loaded]); // eslint-disable-line react-hooks/exhaustive-deps

  const isNew = key === NEW;
  const targets = useApi<Target[] | null>(key && !isNew ? `/projects/${key}/targets` : null);
  const known = (targets.data ?? []).filter((t) => t.kind === kind);
  const rescan = known.some((t) => t.name === target.trim());

  const pick = async (f?: File | null) => {
    if (!f) return;
    // refused here, not after the whole file went up
    const bad = f.size === 0 ? "빈 파일입니다. 내용이 있는 파일을 고르세요."
      : maxMB && f.size > maxMB * 2 ** 20 ? `파일이 너무 큽니다(${fmtSize(f.size)}). 이 서버는 ${fmtLimit(maxMB)}까지 받습니다.` : "";
    setFileErr(bad);
    if (bad) { setFile(null); if (input.current) input.current.value = ""; return; }
    setFile(f);
    if (!targetEdited) setTarget(baseName(f.name));
    setKind(await sniffKind(f));
  };
  const drop = (e: DragEvent) => { e.preventDefault(); setOver(false); void pick(e.dataTransfer.files[0]); };

  const nameErr = isNew && !newName.trim() ? "프로젝트 이름을 입력하세요." : newName.trim().length > 100 ? "이름은 100자 이하로 입력하세요." : "";
  const keyErr = !isNew ? "" : conflict ? "이미 쓰는 키입니다. 다른 키를 입력하세요." : !newKey ? "키를 입력하세요." : !KEY_RE.test(newKey) ? "영문 소문자, 숫자, 하이픈(-)으로 2~40자. 첫 글자는 영문 소문자나 숫자여야 합니다." : "";
  const errs = { file: file ? "" : "검사할 파일을 고르세요.", project: key ? "" : "프로젝트를 고르세요.", name: nameErr, key: keyErr, target: target.trim() ? "" : "대상 이름을 입력하세요." };

  const submit = async () => {
    setTried(true);
    if (!file || Object.values(errs).some(Boolean)) return;
    let projectKey = key, projectName = writable.find((p) => p.key === key)?.name ?? key;
    const base: Run = { file: file.name, target: target.trim(), projectKey, projectName, pct: 0, scanId: null, startedAt: Date.now() };
    if (isNew) {
      try {
        const p = await api.post<Project>("/projects", { key: newKey, name: newName.trim(), description: "" });
        await qc.invalidateQueries({ queryKey: ["/projects"] });
        projectKey = p.key; projectName = p.name;
        setKey(p.key); setNewName(""); setNewKey(""); setKeyEdited(false); // a retry reuses it instead of creating another
      } catch (e) {
        if ((e as ApiError).status === 409) { setConflict(true); return; }
        setEditing(false); setRun({ ...base, projectName: newName.trim(), error: `프로젝트를 만들지 못했습니다. ${(e as ApiError).message}` });
        return;
      }
    }
    try { localStorage.setItem(LAST_PROJECT, projectKey); } catch { /* storage blocked */ }
    const fd = new FormData();
    fd.set("target", base.target); fd.set("kind", kind); fd.set("file", file);
    const cur: Run = { ...base, projectKey, projectName };
    setEditing(false); setRun(cur);
    try {
      const { scan_id } = await uploadJob(projectKey, fd, (pct) => setRun((r) => r && { ...r, pct }), xhr);
      setRun((r) => r && { ...r, pct: 100, scanId: scan_id, startedAt: Date.now() });
    } catch (e) {
      if ((e as ApiError).code === "aborted") { setEditing(true); setRun(null); } else setRun((r) => r && { ...r, error: (e as ApiError).message });
    } finally { xhr.current = null; }
  };
  const again = () => { setRun(null); setEditing(true); setFile(null); setFileErr(""); setTarget(""); setTargetEdited(false); setTried(false); if (input.current) input.current.value = ""; };

  if (run && !editing) return <ScanRun run={run} onCancelUpload={() => xhr.current?.abort()} onAgain={again} onEdit={() => setEditing(true)} />;

  return (
    <form className="panel scan-form" noValidate onSubmit={(e) => { e.preventDefault(); if (!noDb) void submit(); }}>
      <section className="scan-part" aria-labelledby="h-file">
        <h2 id="h-file"><span className="scan-part-n" aria-hidden="true">1</span>검사할 파일</h2>
        <div className={`dropzone${over ? " over" : ""}${file ? " has-file" : ""}`} role="button" tabIndex={0} aria-label={file ? `고른 파일 ${file.name}. 눌러서 바꾸기` : "검사할 파일 선택"}
          aria-describedby={fileErr || (tried && errs.file) ? "scan-file-err" : undefined}
          onClick={() => input.current?.click()} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={drop}>
          {file ? <><Icon name="fileText" size={20} /><span><strong>{file.name}</strong> <span className="muted num">{fmtSize(file.size)}</span></span><span className="dropzone-change">바꾸기</span></>
            : <><strong>파일을 여기에 끌어다 놓거나 눌러서 고르세요</strong><span className="muted">프로젝트 폴더를 압축한 zip·tar·tar.gz 또는 docker save로 만든 이미지 tar{maxMB ? ` · 최대 ${fmtLimit(maxMB)}` : ""}</span></>}
          <input ref={input} type="file" hidden aria-hidden="true" tabIndex={-1} onChange={(e) => void pick(e.target.files?.[0])} />
        </div>
        {(fileErr || (tried && errs.file)) && <p id="scan-file-err" className="field-err" role="alert">{fileErr || errs.file}</p>}
        {file && (
          <fieldset className="seg" aria-describedby="scan-kind-hint">
            <legend>파일 종류</legend>
            {(Object.keys(KIND_TEXT) as Kind[]).map((k) => (
              <label key={k} className={kind === k ? "is-on" : undefined}>
                <input type="radio" name="scan-kind" value={k} checked={kind === k} onChange={() => setKind(k)} />{KIND_TEXT[k][0]}
              </label>
            ))}
            <p id="scan-kind-hint" className="field-hint">{KIND_TEXT[kind][1]}. 파일을 보고 자동으로 골랐습니다. 다르면 바꾸세요.</p>
          </fieldset>
        )}
      </section>

      <section className="scan-part" aria-labelledby="h-where">
        <h2 id="h-where"><span className="scan-part-n" aria-hidden="true">2</span>결과를 저장할 곳</h2>
        <Field label="프로젝트" required error={tried ? errs.project || undefined : undefined}>
          <select className="input" value={key} onChange={(e) => { setKey(e.target.value); setConflict(false); }}>
            {!isNew && !key && <option value="">프로젝트를 고르세요</option>}
            {writable.map((p) => <option key={p.key} value={p.key}>{p.name} ({p.key})</option>)}
            <option value={NEW}>+ 새 프로젝트 만들기</option>
          </select>
        </Field>
        {isNew && (
          <div className="scan-new-project">
            <Field label="새 프로젝트 이름" required error={tried ? nameErr || undefined : undefined}>
              <input className="input" value={newName} maxLength={120} placeholder="예: 결제 API"
                onChange={(e) => { setNewName(e.target.value); if (!keyEdited) setNewKey(suggestKey(e.target.value)); }} />
            </Field>
            <Field label="프로젝트 키" required error={(tried || conflict || (keyEdited && newKey)) ? keyErr || undefined : undefined}
              hint="주소와 CI 명령에 들어가는 영문 이름입니다. 나중에 바꿀 수 없습니다.">
              <input className="input mono" value={newKey} maxLength={40} placeholder="예: payment-api" spellCheck={false}
                onChange={(e) => { setNewKey(e.target.value.toLowerCase()); setKeyEdited(true); setConflict(false); }} />
            </Field>
          </div>
        )}
        <Field label="대상 이름" required error={tried ? errs.target || undefined : undefined}
          hint={!target.trim() ? "서비스나 이미지 이름을 쓰세요(예: web-app). 같은 이름으로 다시 스캔하면 이전 결과와 비교합니다."
            : rescan ? "이미 있는 대상입니다. 이전 스캔과 비교해 새로 생긴 것과 사라진 것을 보여 줍니다." : "새 대상으로 등록됩니다. 다음에 같은 이름으로 스캔하면 이번 결과와 비교합니다."}>
          <input className="input" value={target} list="scan-targets" maxLength={200} placeholder="예: web-app"
            onChange={(e) => { setTarget(e.target.value); setTargetEdited(true); }} />
        </Field>
        <datalist id="scan-targets">{known.map((t) => <option key={t.id} value={t.name} />)}</datalist>
      </section>

      <div className="scan-submit">
        <Button type="submit" variant="primary" icon="scan" disabled={noDb}>스캔 시작</Button>
        {run?.error && <span className="muted">이전 시도: {run.error}</span>}
      </div>
    </form>
  );
}

function HarborTab() {
  const { data: me } = useMe();
  return (
    <Panel title="Harbor 연동">
      <div className="stack">
        <p>Harbor에 이미지를 푸시하면 Harbor가 웹훅으로 JASCA에 알리고, JASCA가 Harbor의 Trivy 보고서를 가져와 자동으로 등록합니다. 사용자가 따로 올릴 필요가 없습니다.</p>
        <ol className="steps">
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
  const tab = sp.get("tab") === "harbor" ? "harbor" : "upload";
  const projects = useApi<Project[]>("/projects");
  const list = projects.data ?? [];
  const { data: me } = useMe();
  const noDb = useAuthConfig().data?.trivy_db_ready === false; // no scan can run: say so before anyone picks a 2GB file
  return (
    <>
      <PageHeader title="스캔하기" description="파일을 올리면 서버가 바로 검사합니다. Harbor를 쓰면 이미지를 푸시할 때 자동으로 등록할 수도 있습니다." />
      <div className="page-narrow">
        <Tabs label="스캔 방법" value={tab} onChange={(t) => setSp({ tab: t }, { replace: true })}
          tabs={[{ id: "upload", label: "파일 올려서 검사" }, { id: "harbor", label: "Harbor에서 자동으로" }]} />
        {projects.error && <div className="alert alert-danger" role="alert">{projects.error.message}</div>}
        {noDb && tab === "upload" && (
          <div className="alert alert-warn" role="alert">
            <Icon name="alert" />
            <span><b>취약점 DB가 아직 설치되지 않아 스캔할 수 없습니다.</b> {isAdmin(me) ? <><Link to="/admin/trivy">관리 → Trivy DB</Link>에서 db.tar.gz를 올리세요.</> : "관리자에게 요청하세요."}</span>
          </div>
        )}
        <div role="tabpanel" id={`tabpanel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === "harbor" ? <HarborTab /> : <UploadTab projects={list} loaded={projects.isSuccess} />}
        </div>
      </div>
    </>
  );
}
