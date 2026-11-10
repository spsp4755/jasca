import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import Field from "../../components/Field";
import { useApi, useUnloadGuard } from "../../api/hooks";
import { API_BASE, ApiError, api } from "../../api/client";
import { daysUntil, fmtDate, fmtDateTime, fmtRelative } from "../../lib/format";
import { useToast } from "../../components/Toast";
import { SEVERITIES, type TrivyOptions, type TrivyPkgType, type TrivyScanner, type TrivyStatus, type TrivyUpload } from "../../api/types";
import { Loading, Panel } from "./parts";
import { RecheckRuns } from "./Recheck";

type DbKind = TrivyUpload["kind"];
const DB: Record<DbKind, { title: string; file: string }> = {
  db: { title: "취약점 DB", file: "db.tar.gz" },
  "java-db": { title: "Java DB", file: "javadb.tar.gz" },
};

/** Upload with progress; plain XHR because fetch has no upload progress. The answer says which DB the file was. */
function upload(file: File, onProgress: (pct: number) => void): Promise<TrivyUpload> {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", `${API_BASE}/admin/trivy/db`);
    x.setRequestHeader("Accept", "application/json");
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    x.onload = () => {
      let body: Partial<TrivyUpload> & { message?: string } = {};
      try { body = JSON.parse(x.responseText); } catch { /* non-JSON */ }
      if (x.status >= 200 && x.status < 300 && body.kind) return resolve(body as TrivyUpload);
      reject(new Error(body.message || `업로드하지 못했습니다. (${x.status})`));
    };
    x.onerror = () => reject(new Error("서버에 연결하지 못했습니다. 네트워크를 확인하세요."));
    const fd = new FormData();
    fd.append("file", file);
    x.send(fd);
  });
}

/**
 * One DB: state, what it is for, and its own upload button and progress. The server tells the two files apart by
 * content, so a file picked under the wrong block is still installed; onApplied gets what it really was.
 */
function DbBlock({ kind, installed, applied, flash, onApplied, children }: {
  kind: DbKind; installed: boolean; applied: boolean; flash: boolean; onApplied: (r: TrivyUpload, under: DbKind) => void; children: ReactNode;
}) {
  const toast = useToast();
  const hid = useId();
  const input = useRef<HTMLInputElement>(null);
  const [pct, setPct] = useState<number | null>(null);
  useUnloadGuard(pct !== null); // a reload would throw away an upload of up to 1GB
  const { title, file } = DB[kind];

  async function pick(f?: File) {
    if (!f) return;
    setPct(0);
    try { onApplied(await upload(f, setPct), kind); } catch (e) { toast((e as Error).message, "error"); }
    setPct(null);
    if (input.current) input.current.value = "";
  }

  return (
    <section className={`panel db-block${flash ? " db-flash" : ""}`} aria-labelledby={hid}>
      <div className="panel-head">
        <h2 id={hid}>{title}</h2>
        <span className={`status status-${installed ? "ok" : kind === "db" ? "danger" : "warn"}`}>
          <span className="status-dot" aria-hidden="true" />{installed ? "설치됨" : "설치 안 됨"}
        </span>
        <code className="panel-meta mono">{file}</code>
      </div>
      <div className="panel-body">
        {children}
        <div className="admin-actions">
          <input ref={input} type="file" accept=".gz,.tgz,application/gzip" hidden onChange={(e) => pick(e.target.files?.[0])} />
          <Button variant={installed ? "secondary" : "primary"} disabled={pct !== null} onClick={() => input.current?.click()}>
            {installed ? `새 ${file}로 교체` : `${file} 올리기`}
          </Button>
          {pct !== null && (
            <>
              <div className="progress" style={{ width: 160 }} role="progressbar" aria-label={`${title} 업로드 진행률`} aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${pct}%` }} /></div>
              <span className="num">{pct}%{pct === 100 && " · 검증 중"}</span>
            </>
          )}
          {pct === null && applied && <span className="tag">방금 적용됨</span>}
        </div>
      </div>
    </section>
  );
}

const SCANNERS: [TrivyScanner, string, string][] = [
  ["vuln", "취약점", "OS·라이브러리 패키지의 알려진 취약점(CVE)을 찾습니다. 보통 켜 둡니다."],
  ["secret", "비밀값", "코드·이미지에 들어간 키, 비밀번호를 찾습니다."],
  ["misconfig", "설정 오류", "Dockerfile, Kubernetes YAML 등의 잘못된 설정을 찾습니다. 결과가 많아지므로 인프라 설정까지 관리할 때 켭니다."],
];
const PKG_TYPES: [TrivyPkgType, string, string][] = [
  ["os", "OS 패키지", "apk, deb, rpm처럼 베이스 이미지에 들어 있는 패키지. 끄면 애플리케이션 라이브러리만 봅니다."],
  ["library", "언어 라이브러리", "npm, pip, Maven, Go 모듈 등. 끄면 OS 패키지만 봅니다."],
];
const PRIORITIES: [TrivyOptions["detection_priority"], string, string][] = [
  ["precise", "정확하게 (기본)", "확실한 것만 보고합니다. 오탐이 적습니다."],
  ["comprehensive", "빠짐없이", "근거가 약해도 보고해 놓치는 것이 줄지만 오탐이 늘어납니다. 누락이 더 큰 문제일 때 고릅니다."],
];

const optionsOf = (s: TrivyOptions): TrivyOptions => ({
  scanners: s.scanners, pkg_types: s.pkg_types, include_dev_deps: s.include_dev_deps, severities: s.severities, ignore_unfixed: s.ignore_unfixed,
  skip_dirs: s.skip_dirs, skip_files: s.skip_files, detection_priority: s.detection_priority, timeout_min: s.timeout_min,
});
/** all without k if cur has it, with k otherwise; always in all's order. */
const toggle = <T,>(all: T[], cur: T[], k: T) => all.filter((x) => (x === k ? !cur.includes(k) : cur.includes(x)));
const lines = (v: string) => v.split("\n").map((x) => x.trim()).filter(Boolean);

/** A checkbox or radio with its name and a one-line explanation. */
function Choice({ type = "checkbox", name, checked, onChange, label, hint }: {
  type?: "checkbox" | "radio"; name?: string; checked: boolean; onChange: (v: boolean) => void; label: string; hint: string;
}) {
  return (
    <label className="choice">
      <input type={type} name={name} checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span><b>{label}</b><span className="muted">{hint}</span></span>
    </label>
  );
}

/** The options every server-side Trivy run gets. One save; the whole object is sent. */
function ScanOptions({ current, defaultTimeout }: { current: TrivyOptions; defaultTimeout: number }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [f, setF] = useState(current);
  const [dirs, setDirs] = useState(current.skip_dirs.join("\n"));
  const [files, setFiles] = useState(current.skip_files.join("\n"));
  const save = useMutation<TrivyStatus, ApiError, TrivyOptions>({
    mutationFn: (o) => api.put<TrivyStatus>("/admin/trivy", o),
    // the page keys this form by the stored options, so the answer resets it to what the server kept
    onSuccess: (st) => { qc.setQueryData(["/admin/trivy"], st); toast("스캔 옵션을 저장했습니다. 다음 스캔과 재평가부터 적용됩니다.", "ok"); },
  });
  const set = (p: Partial<TrivyOptions>) => { setF((c) => ({ ...c, ...p })); save.reset(); };
  const next: TrivyOptions = { ...f, skip_dirs: lines(dirs), skip_files: lines(files) };
  const changed = JSON.stringify(next) !== JSON.stringify(current);
  const problem = !next.scanners.length ? "스캐너를 하나 이상 고르세요."
    : !next.pkg_types.length ? "패키지 종류를 하나 이상 고르세요."
    : !next.severities.length ? "결과에 넣을 심각도를 하나 이상 고르세요." : "";
  const error = problem || save.error?.message;

  return (
    <Panel title="스캔 옵션">
      <p className="muted">서버 스캔, SBOM(CycloneDX) 업로드 평가, 재평가처럼 서버가 Trivy를 직접 실행할 때 똑같이 적용되고, CI나 Harbor에서 올라온 보고서는 이미 검사가 끝난 결과라 바뀌지 않습니다.</p>
      <form className="opt-form" onSubmit={(e) => { e.preventDefault(); if (changed && !problem) save.mutate(next); }}>
        <div className="opt-group">
          <h3>무엇을 검사할지</h3>
          <fieldset className="opt-set">
            <legend className="field-label">스캐너</legend>
            <div className="opt-cols">
              {SCANNERS.map(([k, label, hint]) => (
                <Choice key={k} label={label} hint={hint} checked={f.scanners.includes(k)} onChange={() => set({ scanners: toggle(SCANNERS.map(([s]) => s), f.scanners, k) })} />
              ))}
            </div>
          </fieldset>
          <fieldset className="opt-set">
            <legend className="field-label">패키지 종류</legend>
            <div className="opt-cols">
              {PKG_TYPES.map(([k, label, hint]) => (
                <Choice key={k} label={label} hint={hint} checked={f.pkg_types.includes(k)} onChange={() => set({ pkg_types: toggle(PKG_TYPES.map(([s]) => s), f.pkg_types, k) })} />
              ))}
            </div>
          </fieldset>
          <Choice label="개발용 의존성도 검사" checked={f.include_dev_deps} onChange={(v) => set({ include_dev_deps: v })}
            hint="npm·yarn·gradle의 개발용 의존성(devDependencies)까지 검사합니다. 빌드·테스트 도구의 취약점도 관리할 때 켭니다. 소스·패키지 압축 파일 스캔에만 적용됩니다." />
        </div>

        <div className="opt-group">
          <h3>결과에서 제외할 것</h3>
          <p className="field-hint">여기서 제외한 항목(심각도, 조치 버전 없음, 건너뛴 경로)은 다음 스캔부터 결과에 들어오지 않고, 이미 열려 있던 항목은 그 스캔에서 '해결됨'으로 바뀝니다. 옵션을 되돌리면 다음 스캔에서 다시 열립니다. 위에서 패키지 종류를 끈 경우도 같습니다. 스캐너를 끈 경우는 다릅니다. 그 종류는 아예 검사하지 않으므로, 이미 열려 있던 결과는 '해결됨'으로 바뀌지 않고 열린 채 남습니다.</p>
          <fieldset className="opt-set" aria-describedby="opt-sev-hint">
            <legend className="field-label">결과에 넣을 심각도</legend>
            <div className="opt-sevs">
              {SEVERITIES.map((sv) => (
                <label key={sv} className="check-row">
                  <input type="checkbox" checked={f.severities.includes(sv)} onChange={() => set({ severities: toggle(SEVERITIES, f.severities, sv) })} />{sv}
                </label>
              ))}
            </div>
            <p id="opt-sev-hint" className="field-hint">체크한 심각도만 결과에 넣습니다. 예: LOW와 UNKNOWN을 끄면 조치가 급한 항목만 남습니다. 취약점·비밀값·설정 오류 모두에 적용됩니다.</p>
          </fieldset>
          <Choice label="조치 버전이 없는 취약점 제외" checked={f.ignore_unfixed} onChange={(v) => set({ ignore_unfixed: v })}
            hint="패치가 아직 나오지 않아 버전을 올려도 해결되지 않는 취약점을 뺍니다. 지금 조치할 수 있는 것만 보고 싶을 때 켭니다." />
          <div className="opt-cols">
            <Field label="건너뛸 디렉터리" hint="서버 스캔(압축 파일·이미지)에서 이 경로 아래는 읽지 않습니다. 한 줄에 하나씩, 최대 50개. 예: node_modules, **/testdata">
              <textarea className="input mono" rows={4} spellCheck={false} value={dirs} onChange={(e) => { setDirs(e.target.value); save.reset(); }} />
            </Field>
            <Field label="건너뛸 파일" hint="테스트용 키처럼 오탐을 내는 파일을 뺄 때 씁니다. 한 줄에 하나씩, 최대 50개. 예: **/*.min.js, **/fixtures/*.pem">
              <textarea className="input mono" rows={4} spellCheck={false} value={files} onChange={(e) => { setFiles(e.target.value); save.reset(); }} />
            </Field>
          </div>
        </div>

        <div className="opt-group">
          <h3>고급</h3>
          <fieldset className="opt-set">
            <legend className="field-label">탐지 방식</legend>
            <div className="opt-cols">
              {PRIORITIES.map(([k, label, hint]) => (
                <Choice key={k} type="radio" name="detection_priority" label={label} hint={hint} checked={f.detection_priority === k} onChange={() => set({ detection_priority: k })} />
              ))}
            </div>
          </fieldset>
          <Field label="스캔 1건 제한 시간 (분)" hint={`이 시간을 넘긴 스캔은 중단하고 실패로 표시합니다. 큰 이미지가 시간 초과로 실패하면 늘리세요. 1~240분, 비워 두면 서버 기본값(${defaultTimeout}분)을 씁니다.`}>
            <input className="input opt-num" type="number" min={1} max={240} placeholder={String(defaultTimeout)} value={f.timeout_min || ""}
              onChange={(e) => set({ timeout_min: Number(e.target.value) || 0 })} />
          </Field>
        </div>

        {error && <p className="field-err" role="alert">{error}</p>}
        <div className="admin-actions">
          <Button type="submit" variant="primary" disabled={!changed || !!problem} loading={save.isPending}>저장</Button>
        </div>
      </form>
    </Panel>
  );
}

export default function Trivy() {
  const q = useApi<TrivyStatus>("/admin/trivy");
  const qc = useQueryClient();
  const toast = useToast();
  const [applied, setApplied] = useState<DbKind[]>([]); // "방금 적용됨" stays until the admin leaves the page
  const [flash, setFlash] = useState<DbKind | null>(null);
  useEffect(() => {
    if (!flash) return;
    const t = setTimeout(() => setFlash(null), 2500);
    return () => clearTimeout(t);
  }, [flash]);
  const s = q.data;
  // trivy-db's next_update is about a day after its build, so an air-gapped copy is always a little past it
  const late = s?.next_update ? -daysUntil(s.next_update) : 0;
  const stale = late >= 7;

  function onApplied(r: TrivyUpload, under: DbKind) {
    const what = DB[r.kind].title;
    const made = fmtDate(r.kind === "db" ? r.updated_at : r.java_db?.updated_at);
    // only a new vulnerability DB starts a recheck; the server says so with recheck_run_id
    const then = r.kind === "java-db" ? " 다음 서버 스캔부터 JAR/WAR/EAR 파일을 검사합니다." : r.recheck_run_id ? " 저장된 결과의 재평가를 시작했습니다." : "";
    toast(`${r.kind !== under ? `올린 파일이 ${what}여서 ` : ""}${what}를 적용했습니다 (${made} 생성).${then}`, "ok");
    setApplied((a) => (a.includes(r.kind) ? a : [...a, r.kind]));
    setFlash(r.kind);
    qc.setQueryData(["/admin/trivy"], r);
    qc.invalidateQueries({ queryKey: ["/admin/recheck"] });
    qc.invalidateQueries({ queryKey: ["/auth/config"] }); // trivy_db_ready: the scan page stops saying there is no DB
  }

  return (
    <>
      <PageHeader title="Trivy DB" description="폐쇄망이라 DB는 인터넷 PC에서 받아 직접 올립니다. 잘못된 파일은 거부되고 기존 DB가 유지됩니다."
        actions={s?.trivy_version && <span className="tag tag-quiet">Trivy {s.trivy_version}</span>} />
      <Loading q={q} />
      {stale && <div className="alert alert-warn" role="alert">취약점 DB가 오래되었습니다. 다음 갱신 예정일({fmtDateTime(s!.next_update!)})에서 7일 넘게 지났습니다. 새 DB를 올려 주세요.</div>}
      {s && (
        <div className="db-grid">
          <DbBlock kind="db" installed={s.db_version > 0} applied={applied.includes("db")} flash={flash === "db"} onApplied={onApplied}>
            <p>알려진 취약점 목록입니다. 서버 스캔과 재평가에 꼭 필요합니다.</p>
            {s.db_version > 0 ? (
              <dl className="kv">
                <div className="kv-row"><dt>생성 시각</dt><dd>{fmtDateTime(s.updated_at)} <span className="muted">· {fmtRelative(s.updated_at)}</span></dd></div>
                <div className="kv-row"><dt>다음 갱신 예정</dt><dd>{fmtDateTime(s.next_update)}{late > 0 && <span className="muted"> · {late}일 지남</span>}</dd></div>
                <div className="kv-row"><dt>DB 형식</dt><dd className="num">v{s.db_version}</dd></div>
              </dl>
            ) : null}
            <p className={`db-next${stale ? " db-next-warn" : ""}`}>
              {s.db_version === 0 ? "아직 올린 DB가 없습니다. 서버 스캔과 재평가를 하려면 db.tar.gz를 올리세요."
                : stale ? "인터넷 PC에서 새 db.tar.gz를 받아 교체하세요."
                : "새 DB는 매일 나옵니다. 일주일에 한 번은 새 파일로 교체하세요. 교체하면 저장된 결과를 자동으로 재평가합니다."}
            </p>
          </DbBlock>
          <DbBlock kind="java-db" installed={!!s.java_db} applied={applied.includes("java-db")} flash={flash === "java-db"} onApplied={onApplied}>
            <p>JAR/WAR/EAR 파일 안의 Java 라이브러리를 알아내는 데 필요합니다. 서버 스캔이 압축 파일(소스 코드·패키지)과 컨테이너 이미지 양쪽에서 이 파일들을 검사할 때 씁니다. 없으면 그 파일만 건너뛰고 나머지를 검사하며, 스캔 결과에 검사하지 못한 Java 파일이 있다고 표시합니다. pom.xml 같은 잠금 파일은 Java DB 없이도 검사합니다.</p>
            {s.java_db ? (
              <dl className="kv">
                <div className="kv-row"><dt>생성 시각</dt><dd>{fmtDateTime(s.java_db.updated_at)} <span className="muted">· {fmtRelative(s.java_db.updated_at)}</span></dd></div>
              </dl>
            ) : null}
            <p className="db-next">
              {s.java_db ? "다음 서버 스캔부터 적용됩니다. 이미 끝난 스캔에는 반영되지 않으니, Java 파일이 든 대상은 다시 스캔하세요."
                : "Java 애플리케이션을 스캔한다면 javadb.tar.gz를 올리세요. 취약점 DB와 따로 올립니다."}
            </p>
          </DbBlock>
        </div>
      )}
      {s && (
        <details className="panel db-help" open={s.db_version === 0 || undefined}>
          <summary>인터넷 PC에서 파일 받는 방법</summary>
          <div className="panel-body">
            <ol className="steps">
              <li>인터넷이 되는 PC에 <a href="https://oras.land" target="_blank" rel="noreferrer">oras</a>를 설치합니다.</li>
              <li>취약점 DB를 받습니다. 현재 디렉터리에 <code>db.tar.gz</code>가 생깁니다.
                <pre className="code">oras pull ghcr.io/aquasecurity/trivy-db:2</pre></li>
              <li>Java 라이브러리(jar) 검사가 필요하면 Java DB도 받습니다. <code>javadb.tar.gz</code>가 생깁니다.
                <pre className="code">oras pull ghcr.io/aquasecurity/trivy-java-db:1</pre></li>
              <li>파일을 USB 등으로 옮겨 위의 해당 칸에서 올립니다. 칸을 잘못 골라도 파일 내용으로 구분해 맞는 DB에 적용합니다.</li>
            </ol>
          </div>
        </details>
      )}
      {s && <ScanOptions key={JSON.stringify(optionsOf(s))} current={optionsOf(s)} defaultTimeout={s.default_timeout_min} />}
      <RecheckRuns />
    </>
  );
}
