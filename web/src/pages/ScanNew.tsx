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
import { SEVERITIES, type Counts, type Dashboard, type Project, type ScanDetail, type ScanJobCreated, type Target } from "../api/types";
import { copyText } from "../lib/clipboard";
import { SEVERITY_LABEL, fmtDateTime, fmtNumber, fmtRelative } from "../lib/format";
import StatusBadge from "../components/StatusBadge";
import { ProjectTarget, SummaryCell } from "./Home";
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
// how to make each kind of file: [title, where to run it, command, what gets read]
const PREP: [string, string, string, string][] = [
  ["소스 코드·패키지", "프로젝트 폴더 안에서", "tar czf ../app.tar.gz --exclude=.git .",
    "의존성 잠금 파일(package-lock.json, go.mod, pom.xml, requirements.txt 등)과 JAR·WAR 파일을 읽습니다. Windows에서는 폴더를 zip으로 압축해도 됩니다."],
  ["컨테이너 이미지", "이미지가 있는 서버에서", "docker save -o app.tar 이미지:태그",
    "OS 패키지와 이미지 안의 라이브러리를 읽습니다. podman save도 같은 형식입니다."],
];

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
/** "app-1.4.2" → ["app", "1.4.2"]. A version in the target name makes every release a new target, whose findings then never close. */
const splitVersion = (s: string): [string, string] => {
  const m = /^(.+?)[-_@:]((?:v?\d+(?:\.\d+)+(?:[-.+_][0-9A-Za-z]+)*)|v?\d+)$/.exec(s);
  return m ? [m[1], m[2]] : [s, ""];
};
const stem = (name: string) => splitVersion(name.trim())[0].toLowerCase();
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

/** A scan by id, polled until it is done, failed or canceled. */
const useScan = (id: number | null) => useApi<ScanDetail>(id ? `/scans/${id}` : null,
  { refetchInterval: (query) => (query.state.data && DONE.includes(query.state.data.status) ? false : 2000), staleTime: 0 });

/** One of several files picked at once: each becomes its own scan of its own target. */
type Item = { file: File; target: string; ref: string; kind: Kind };
const CANCELED = "업로드를 취소했습니다.";

/** startedAt: when the upload finished and the wait for the server began (the upload has its own percentage). */
type Run = { file: string; target: string; projectKey: string; projectName: string; pct: number; scanId: number | null; startedAt: number; error?: string };

/** Upload → scan → result, in place of the form while a run is going. */
function ScanRun({ run, onCancelUpload, onAgain, onEdit }: { run: Run; onCancelUpload: () => void; onAgain: () => void; onEdit: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useScan(run.scanId);
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
            {s.policy && (s.policy.disabled
              ? <p className="scan-policy muted">이 프로젝트는 정책을 쓰지 않습니다(정책 사용 안 함).</p>
              : s.policy.passed
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

/** One file of a batch: waiting its turn, going up, then the scan's own status and counts. */
function BatchRow({ run, waiting }: { run: Run; waiting: boolean }) {
  const qc = useQueryClient();
  const q = useScan(run.scanId);
  const s = q.data;
  useEffect(() => { if (s?.status === "done") qc.invalidateQueries({ queryKey: ["/projects"] }); }, [s?.status, qc]);
  const failed = run.error || (s?.status === "failed" ? s.error || "스캔에 실패했습니다." : q.error?.message);
  const warning = s?.status === "done" ? s.summary.warnings?.[0] : undefined; // "없음" must not hide what was not examined
  return (
    <li>
      <span className="scan-batch-name">
        <strong>{run.target}</strong>
        <span className="muted">{run.file}</span>
        {failed && failed !== CANCELED && <span className="field-err">{failed}</span>}
        {warning && <span className="scan-batch-warn">{warning}</span>}
      </span>
      {run.error ? <StatusBadge status={run.error === CANCELED ? "canceled" : "failed"} />
        : waiting ? <span className="muted nw">차례를 기다리는 중</span>
        : !run.scanId ? <><span className="muted num nw">올리는 중 {run.pct}%</span><div className="progress" role="progressbar" aria-label={`${run.file} 업로드 진행률`} aria-valuenow={run.pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${run.pct}%` }} /></div></>
        : s?.status === "done" ? <SummaryCell s={s.summary} /> : <StatusBadge status={s?.status ?? "queued"} />}
      {run.scanId && <Link className="btn btn-secondary btn-sm" to={`/scans/${run.scanId}`} aria-label={`${run.target} ${s?.status === "done" ? "결과 보기" : "스캔 기록"}`}>{s?.status === "done" ? "결과 보기" : "스캔 기록"}</Link>}
    </li>
  );
}

/** Several files: they go up one after another, and each row then follows its own scan. */
function BatchRun({ runs, active, onCancel, onAgain, onRetry }: { runs: Run[]; active: number; onCancel: () => void; onAgain: () => void; onRetry: () => void }) {
  const up = active >= 0;
  const sent = runs.filter((r) => r.scanId).length, lost = runs.filter((r) => r.error).length;
  return (
    <section className="panel scan-run" aria-labelledby="h-run">
      <div className="panel-head">
        <h2 id="h-run">파일 {runs.length}개 스캔</h2>
        <span className="panel-meta">{runs[0].projectName} 프로젝트에 저장</span>
      </div>
      <ul className="scan-batch-runs">{runs.map((r, i) => <BatchRow key={i} run={r} waiting={up && i > active} />)}</ul>
      <div className="panel-body stack">
        <p className="muted" role="status" style={{ margin: 0 }}>
          {up ? `파일을 차례로 올리고 있습니다(${active + 1}/${runs.length}). 올리는 동안 이 화면을 닫지 마세요.`
            : `${runs.length}개 중 ${sent}개를 올렸습니다${lost ? `(${lost}개는 올리지 못했습니다)` : ""}. 서버가 차례로 검사하며, 화면을 떠나도 검사는 계속됩니다.`}
        </p>
        <div className="row-gap">
          {up ? <Button onClick={onCancel}>남은 업로드 취소</Button> : (
            <>
              <Link className="btn btn-primary" to={`/projects/${runs[0].projectKey}/scans`}>프로젝트 스캔 기록</Link>
              {lost > 0 && <Button onClick={onRetry}>올리지 못한 파일 다시 시도</Button>}
              <Button onClick={onAgain}>다른 파일 스캔</Button>
            </>
          )}
        </div>
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
  const [ref, setRef] = useState("");
  const [refEdited, setRefEdited] = useState(false);
  const [kind, setKind] = useState<Kind>("fs");
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [tried, setTried] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [batch, setBatch] = useState<Item[]>([]); // filled instead of `file` when several files are picked
  const [runs, setRuns] = useState<Run[]>([]);
  const [active, setActive] = useState(-1); // the run going up now
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
  const uploading = active >= 0;
  useUnloadGuard(uploading);
  const blocker = useBlocker(uploading);
  useEffect(() => {
    if (blocker.state !== "blocked") return;
    if (confirm("파일을 올리는 중입니다. 이 화면을 떠나면 업로드가 취소됩니다. 떠날까요?")) blocker.proceed(); else blocker.reset();
  }, [blocker]);

  // First choice once the list is in: ?project=, then the last one used, then the only one; none at all starts a new project.
  // A ?project= the user may only view chooses nothing: falling back would quietly send the upload to another project.
  const readOnly = projects.find((p) => p.key === sp.get("project") && p.my_role === "viewer");
  useEffect(() => {
    if (!loaded || key || readOnly) return;
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
  // the same service under another version's name: scanning it as a new target would leave the old findings open
  const similar = !rescan && target.trim() ? known.find((t) => stem(t.name) === stem(target)) : undefined;

  const multi = batch.length > 0;
  const pick = async (list?: FileList | null) => {
    const all = Array.from(list ?? []);
    if (input.current) input.current.value = ""; // the same file can be chosen again
    if (!all.length) return;
    // refused here, not after the whole file went up
    const why = (f: File) => f.size === 0 ? "빈 파일입니다. 내용이 있는 파일을 고르세요."
      : maxMB && f.size > maxMB * 2 ** 20 ? `파일이 너무 큽니다(${fmtSize(f.size)}). 이 서버는 ${fmtLimit(maxMB)}까지 받습니다.` : "";
    if (all.length === 1 && !multi) {
      const f = all[0], bad = why(f);
      setFileErr(bad);
      if (bad) { setFile(null); return; }
      setFile(f);
      const [name, version] = splitVersion(baseName(f.name));
      if (!targetEdited) setTarget(name);
      if (!refEdited) setRef(version);
      setKind(await sniffKind(f));
      return;
    }
    // several at once (or more onto a list): one row each, one scan each
    const good = all.filter((f) => !why(f)), bad = all.filter(why);
    setFileErr(bad.length ? `비어 있거나${maxMB ? ` ${fmtLimit(maxMB)}를 넘어` : " 너무 커"} 뺀 파일: ${bad.map((f) => f.name).join(", ")}` : "");
    const kinds = await Promise.all(good.map(sniffKind));
    setFile(null);
    setBatch((b) => [...b, ...good.map((f, i) => { const [name, version] = splitVersion(baseName(f.name)); return { file: f, target: name, ref: version, kind: kinds[i] }; })]);
  };
  const drop = (e: DragEvent) => { e.preventDefault(); setOver(false); void pick(e.dataTransfer.files); };
  const setRow = (i: number, p: Partial<Item>) => setBatch((b) => b.map((x, j) => (j === i ? { ...x, ...p } : x)));
  // Two files onto one target in one go would leave it at whichever scan happens to finish last.
  const names = batch.map((b) => `${b.kind}:${b.target.trim()}`);
  const rowBad = (i: number) => !batch[i].target.trim() || names.indexOf(names[i]) !== names.lastIndexOf(names[i]);
  const batchErr = batch.some((b) => !b.target.trim()) ? "대상 이름이 빈 파일이 있습니다. 모두 채우세요."
    : batch.some((_, i) => rowBad(i)) ? "같은 대상 이름이 두 번 있습니다. 한 대상에는 한 번에 파일 하나만 검사합니다. 이름을 바꾸거나 한 파일을 빼세요." : "";

  const nameErr = isNew && !newName.trim() ? "프로젝트 이름을 입력하세요." : newName.trim().length > 100 ? "이름은 100자 이하로 입력하세요." : "";
  const keyErr = !isNew ? "" : conflict ? "이미 쓰는 키입니다. 다른 키를 입력하세요." : !newKey ? "키를 입력하세요." : !KEY_RE.test(newKey) ? "영문 소문자, 숫자, 하이픈(-)으로 2~40자. 첫 글자는 영문 소문자나 숫자여야 합니다." : "";
  const errs = { file: file || multi ? "" : "검사할 파일을 고르세요.", batch: batchErr, project: key ? "" : "프로젝트를 고르세요.", name: nameErr, key: keyErr, target: multi || target.trim() ? "" : "대상 이름을 입력하세요." };

  const submit = async () => {
    setTried(true);
    const list: Item[] = multi ? batch : file ? [{ file, target, ref, kind }] : [];
    if (!list.length || Object.values(errs).some(Boolean)) return;
    let projectKey = key, projectName = writable.find((p) => p.key === key)?.name ?? key;
    const mk = (): Run[] => list.map((it) => ({ file: it.file.name, target: it.target.trim(), projectKey, projectName, pct: 0, scanId: null, startedAt: Date.now() }));
    if (isNew) {
      try {
        const p = await api.post<Project>("/projects", { key: newKey, name: newName.trim(), description: "" });
        await qc.invalidateQueries({ queryKey: ["/projects"] });
        projectKey = p.key; projectName = p.name;
        setKey(p.key); setNewName(""); setNewKey(""); setKeyEdited(false); // a retry reuses it instead of creating another
      } catch (e) {
        if ((e as ApiError).status === 409) { setConflict(true); return; }
        setEditing(false); setRuns([{ ...mk()[0], projectName: newName.trim(), error: `프로젝트를 만들지 못했습니다. ${(e as ApiError).message}` }]);
        return;
      }
    }
    try { localStorage.setItem(LAST_PROJECT, projectKey); } catch { /* storage blocked */ }
    const patch = (i: number, p: Partial<Run>) => setRuns((rs) => rs.map((r, j) => (j === i ? { ...r, ...p } : r)));
    setEditing(false); setRuns(mk());
    for (let i = 0; i < list.length; i++) { // one at a time: the server takes one file per request and queues the scans
      const it = list[i], fd = new FormData();
      fd.set("target", it.target.trim()); fd.set("kind", it.kind);
      if (it.ref.trim()) fd.set("ref", it.ref.trim());
      fd.set("file", it.file); // last: the server reads the fields before the file
      setActive(i);
      try {
        const { scan_id } = await uploadJob(projectKey, fd, (pct) => patch(i, { pct }), xhr);
        patch(i, { pct: 100, scanId: scan_id, startedAt: Date.now() });
      } catch (e) {
        const { code, message } = e as ApiError;
        if (code !== "aborted" && code !== "no_space") { patch(i, { error: message }); continue; }
        // canceled, or the server's disk is full until the queued scans are through: the files still waiting stop too
        if (code === "aborted" && list.length === 1) { setEditing(true); setRuns([]); }
        else setRuns((rs) => rs.map((r, j) => (j >= i ? { ...r, error: code === "aborted" ? CANCELED : message } : r)));
        break;
      }
    }
    xhr.current = null; setActive(-1);
  };
  const again = () => { setRuns([]); setEditing(true); setFile(null); setBatch([]); setFileErr(""); setTarget(""); setTargetEdited(false); setRef(""); setRefEdited(false); setTried(false); };
  // batch rows and runs share their order; what went up is dropped, the rest is back in the form
  const retry = () => { setBatch(batch.filter((_, i) => runs[i]?.error)); setRuns([]); setEditing(true); setTried(false); };

  // a recent scan's project and target, ready for the next file
  const reuse = (projectKey: string, name: string) => {
    setKey(projectKey); setConflict(false); setTarget(name); setTargetEdited(true);
    try { localStorage.setItem(LAST_PROJECT, projectKey); } catch { /* storage blocked */ }
    (file || multi ? document.querySelector<HTMLElement>(".scan-submit button") : document.querySelector<HTMLElement>(".dropzone"))?.focus();
  };
  const running = runs.length > 0 && !editing;

  return (
    <div className="scan-layout">
      <div className="scan-main">
        {!running ? form()
          : runs.length > 1 ? <BatchRun runs={runs} active={active} onCancel={() => xhr.current?.abort()} onAgain={again} onRetry={retry} />
          : <ScanRun run={runs[0]} onCancelUpload={() => xhr.current?.abort()} onAgain={again} onEdit={() => setEditing(true)} />}
      </div>
      <ScanAside canReuse={(k) => !running && writable.some((p) => p.key === k)} onReuse={reuse} />
    </div>
  );

  function form() { return (
    <form className="panel scan-form" noValidate onSubmit={(e) => { e.preventDefault(); if (!noDb && loaded) void submit(); }}>
      <section className="scan-part" aria-labelledby="h-file">
        <h2 id="h-file"><span className="scan-part-n" aria-hidden="true">1</span>검사할 파일</h2>
        <div className={`dropzone${over ? " over" : ""}${file || multi ? " has-file" : ""}`} role="button" tabIndex={0}
          aria-label={multi ? `고른 파일 ${batch.length}개. 눌러서 더 추가` : file ? `고른 파일 ${file.name}. 눌러서 바꾸기` : "검사할 파일 선택"}
          aria-describedby={fileErr || (tried && errs.file) ? "scan-file-err" : undefined}
          onClick={() => input.current?.click()} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={drop}>
          {multi ? <><Icon name="fileText" size={20} /><span><strong>파일 {batch.length}개</strong> <span className="muted num">{fmtSize(batch.reduce((n, b) => n + b.file.size, 0))}</span></span><span className="dropzone-change">더 추가</span></>
            : file ? <><Icon name="fileText" size={20} /><span><strong>{file.name}</strong> <span className="muted num">{fmtSize(file.size)}</span></span><span className="dropzone-change">바꾸기</span></>
            : <><strong>파일을 여기에 끌어다 놓거나 눌러서 고르세요</strong><span className="muted">프로젝트 폴더를 압축한 zip·tar·tar.gz 또는 docker save로 만든 이미지 tar{maxMB ? ` · 최대 ${fmtLimit(maxMB)}` : ""}</span>
                <span className="muted">여러 개를 한 번에 고르면 파일마다 따로 검사합니다</span></>}
          <input ref={input} type="file" multiple hidden aria-hidden="true" tabIndex={-1} onChange={(e) => void pick(e.target.files)} />
        </div>
        {(fileErr || (tried && errs.file)) && <p id="scan-file-err" className="field-err" role="alert">{fileErr || errs.file}</p>}
        {multi && (
          <>
            <ul className="scan-batch" aria-label="검사할 파일 목록">
              <li className="scan-batch-head" aria-hidden="true"><span>파일</span><span>파일 종류</span><span>대상 이름</span><span>버전</span><span /></li>
              {batch.map((b, i) => (
                <li key={i}>
                  <span className="scan-batch-name" title={b.file.name}><strong>{b.file.name}</strong><span className="muted num">{fmtSize(b.file.size)}</span></span>
                  <select className="input" aria-label={`${b.file.name} 파일 종류`} value={b.kind} onChange={(e) => setRow(i, { kind: e.target.value as Kind })}>
                    {(Object.keys(KIND_TEXT) as Kind[]).map((k) => <option key={k} value={k}>{KIND_TEXT[k][0]}</option>)}
                  </select>
                  <input className="input" aria-label={`${b.file.name} 대상 이름`} aria-invalid={(tried && rowBad(i)) || undefined} value={b.target} maxLength={200} placeholder="대상 이름"
                    onChange={(e) => setRow(i, { target: e.target.value })} />
                  <input className="input mono" aria-label={`${b.file.name} 버전`} value={b.ref} maxLength={200} placeholder="선택" spellCheck={false}
                    onChange={(e) => setRow(i, { ref: e.target.value })} />
                  <Button size="sm" variant="ghost" icon="x" aria-label={`${b.file.name} 빼기`} title="빼기" onClick={() => setBatch(batch.filter((_, j) => j !== i))} />
                </li>
              ))}
            </ul>
            {tried && errs.batch ? <p className="field-err" role="alert">{errs.batch}</p>
              : <p className="field-hint">파일마다 대상 하나로 따로 검사합니다. 파일 종류, 대상 이름, 버전은 파일을 보고 채웠습니다. 같은 서비스는 지난번과 같은 대상 이름으로 두어야 고친 취약점이 조치됨으로 바뀝니다.</p>}
          </>
        )}
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
        {readOnly && !key && <div className="alert alert-warn" role="alert"><Icon name="alert" />{readOnly.name} 프로젝트는 보기 전용이라 스캔을 올릴 수 없습니다. 다른 프로젝트를 고르거나 소유자에게 멤버 권한을 요청하세요.</div>}
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
              <input className="input" value={newName} maxLength={100} placeholder="예: 결제 API"
                onChange={(e) => { setNewName(e.target.value); if (!keyEdited) setNewKey(suggestKey(e.target.value)); }} />
            </Field>
            <Field label="프로젝트 키" required error={(tried || conflict || (keyEdited && newKey)) ? keyErr || undefined : undefined}
              hint="주소와 CI 명령에 들어가는 영문 이름입니다. 나중에 바꿀 수 없습니다.">
              <input className="input mono" value={newKey} maxLength={40} placeholder="예: payment-api" spellCheck={false}
                onChange={(e) => { setNewKey(e.target.value.toLowerCase()); setKeyEdited(true); setConflict(false); }} />
            </Field>
          </div>
        )}
        {!multi && <div className="scan-target-row">
          <Field label="대상 이름" required error={tried ? errs.target || undefined : undefined}
            hint={!target.trim() ? "서비스나 이미지 이름을 쓰세요(예: web-app). 버전은 옆 칸에 쓰세요. 같은 이름으로 다시 스캔해야 고친 취약점이 조치됨으로 바뀝니다."
              : rescan ? "이미 있는 대상입니다. 이전 스캔과 비교해, 사라진 취약점은 조치됨으로 바꿉니다." : "새 대상으로 등록됩니다. 다음 버전도 이 이름으로 스캔하세요."}>
            <input className="input" value={target} list="scan-targets" maxLength={200} placeholder="예: web-app"
              onChange={(e) => { setTarget(e.target.value); setTargetEdited(true); }} />
          </Field>
          <Field label="버전" hint={kind === "image" ? "선택. 비우면 이미지의 태그를 씁니다." : "선택. 스캔 기록에 표시됩니다."}>
            <input className="input mono" value={ref} maxLength={200} placeholder="예: 1.4.2" spellCheck={false}
              onChange={(e) => { setRef(e.target.value); setRefEdited(true); }} />
          </Field>
        </div>}
        {!multi && similar && (
          <div className="alert alert-warn scan-similar" role="status">
            <Icon name="alert" />
            <span>비슷한 대상 <b className="mono">{similar.name}</b>이(가) 있습니다. 같은 서비스의 다른 버전이면 그 대상으로 스캔하세요. 이름이 다르면 다른 대상으로 따로 쌓여, 이전 취약점이 열린 채 남습니다.</span>
            <Button size="sm" onClick={() => { if (!ref.trim()) setRef(splitVersion(target.trim())[1]); setTarget(similar.name); setTargetEdited(true); }}>이 대상으로 스캔</Button>
          </div>
        )}
        <datalist id="scan-targets">{known.map((t) => <option key={t.id} value={t.name} />)}</datalist>
      </section>

      <div className="scan-submit">
        <Button type="submit" variant="primary" icon="scan" disabled={noDb || !loaded}>{multi ? `${batch.length}개 스캔 시작` : "스캔 시작"}</Button>
        {runs.length === 1 && runs[0].error && <span className="muted">이전 시도: {runs[0].error}</span>}
      </div>
    </form>
  ); }
}

/** Beside the form: how to make the file, and the latest scans with a way to scan the same target again. */
function ScanAside({ canReuse, onReuse }: { canReuse: (projectKey: string) => boolean; onReuse: (projectKey: string, target: string) => void }) {
  const toast = useToast();
  const d = useApi<Dashboard>("/dashboard");
  const scans = (d.data?.recent_scans ?? []).filter((s) => s.source === "server" || s.source === "upload").slice(0, 5);
  const copy = async (cmd: string) => ((await copyText(cmd)) ? toast("명령을 복사했습니다.", "ok") : toast("복사하지 못했습니다. 직접 선택해 복사하세요.", "error"));
  return (
    <aside className="scan-aside" aria-label="스캔 도움말과 최근 스캔">
      <section className="panel" aria-labelledby="h-prep">
        <div className="panel-head"><h2 id="h-prep">올릴 파일 만드는 법</h2></div>
        <div className="panel-body scan-prep">
          {PREP.map(([title, where, cmd, reads]) => (
            <div key={title}>
              <h3>{title} <span className="muted">{where}</span></h3>
              <div className="scan-cmd">
                <code>{cmd}</code>
                <Button size="sm" variant="ghost" icon="copy" aria-label={`${title} 명령 복사`} title="복사" onClick={() => void copy(cmd)} />
              </div>
              <p className="field-hint">{reads}</p>
            </div>
          ))}
        </div>
      </section>
      <section className="panel" aria-labelledby="h-recent-scans">
        <div className="panel-head"><h2 id="h-recent-scans">최근 올린 스캔</h2></div>
        {d.isPending ? <div className="panel-body"><div className="skeleton skeleton-block" style={{ height: 96 }} /></div>
          : scans.length === 0 ? <p className="panel-body muted" style={{ margin: 0 }}>아직 없습니다. 스캔을 마치면 여기에서 같은 대상을 다시 스캔할 수 있습니다.</p>
          : (
            <ul className="scan-recent">
              {scans.map((s) => (
                <li key={s.id}>
                  <Link to={`/scans/${s.id}`} className="scan-recent-main">
                    <ProjectTarget project={s.project_key} target={s.target} />
                    <span className="scan-recent-meta">
                      {s.status === "done" ? <SummaryCell s={s.summary} /> : <StatusBadge status={s.status} />}
                      <span className="muted nw" title={fmtDateTime(s.created_at)}>{fmtRelative(s.created_at)}</span>
                    </span>
                  </Link>
                  {canReuse(s.project_key) && <Button size="sm" aria-label={`${s.target} 다시 스캔`} title="이 프로젝트와 대상 이름으로 채웁니다" onClick={() => onReuse(s.project_key, s.target)}>다시</Button>}
                </li>
              ))}
            </ul>
          )}
      </section>
    </aside>
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
          {tab === "harbor" ? <div className="scan-main"><HarborTab /></div> : <UploadTab projects={list} loaded={projects.isSuccess} />}
        </div>
      </div>
    </>
  );
}
