import { useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { API_BASE, ApiError, api } from "../../api/client";
import { daysUntil, fmtDateTime } from "../../lib/format";
import { useToast } from "../../components/Toast";
import type { TrivyScanner, TrivyStatus } from "../../api/types";
import { Loading, Panel } from "./parts";
import { RecheckRuns } from "./Recheck";

/** Upload with progress; plain XHR because fetch has no upload progress. */
function upload(file: File, onProgress: (pct: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", `${API_BASE}/admin/trivy/db`);
    x.setRequestHeader("Accept", "application/json");
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    x.onload = () => {
      if (x.status >= 200 && x.status < 300) return resolve();
      let msg = `업로드하지 못했습니다. (${x.status})`;
      try { msg = JSON.parse(x.responseText).message || msg; } catch { /* non-JSON */ }
      reject(new Error(msg));
    };
    x.onerror = () => reject(new Error("서버에 연결하지 못했습니다. 네트워크를 확인하세요."));
    const fd = new FormData();
    fd.append("file", file);
    x.send(fd);
  });
}

const SCANNERS: [TrivyScanner, string, string][] = [
  ["vuln", "취약점", "OS·라이브러리 패키지의 알려진 취약점"],
  ["secret", "비밀값", "코드·이미지에 들어간 키, 비밀번호"],
  ["misconfig", "설정 오류", "Dockerfile, Kubernetes YAML 등의 잘못된 설정"],
];

/** Which scanners server-side scans (uploads, Harbor) run. */
function ScannerSettings({ current }: { current: TrivyScanner[] }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [sel, setSel] = useState<TrivyScanner[]>(current);
  const save = useMutation<TrivyStatus, ApiError, TrivyScanner[]>({
    mutationFn: (scanners) => api.put<TrivyStatus>("/admin/trivy", { scanners }),
    onSuccess: (st) => { qc.setQueryData(["/admin/trivy"], st); toast("스캐너 설정을 저장했습니다.", "ok"); },
    onError: (e) => toast(e.message, "error"),
  });
  const changed = sel.length !== current.length || sel.some((x) => !current.includes(x));
  return (
    <Panel title="서버 스캔에 쓸 스캐너" meta="서버 스캔(파일을 올려 서버에서 돌리는 스캔)에 적용됩니다. Harbor는 Harbor의 보고서를 그대로 가져옵니다.">
      <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="sr-only">스캐너</legend>
        <div className="stack" style={{ gap: 6 }}>
          {SCANNERS.map(([k, label, hint]) => (
            <label key={k} className="check-row">
              <input type="checkbox" checked={sel.includes(k)}
                onChange={() => setSel((c) => (c.includes(k) ? c.filter((x) => x !== k) : SCANNERS.map(([s]) => s).filter((s) => s === k || c.includes(s))))} />
              <b>{label}</b> <span className="muted">{hint}</span>
            </label>
          ))}
        </div>
      </fieldset>
      {sel.length === 0 && <p className="field-err" role="alert">하나 이상 고르세요.</p>}
      <div className="admin-actions" style={{ marginTop: 12 }}>
        <Button variant="primary" disabled={!changed || sel.length === 0} loading={save.isPending} onClick={() => save.mutate(sel)}>저장</Button>
      </div>
    </Panel>
  );
}

export default function Trivy() {
  const q = useApi<TrivyStatus>("/admin/trivy");
  const qc = useQueryClient();
  const toast = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [pct, setPct] = useState<number | null>(null);
  const s = q.data;
  // trivy-db's next_update is about a day after its build, so an air-gapped copy is always a little past it
  const stale = !!s?.next_update && daysUntil(s.next_update) <= -7;

  async function pick(file?: File) {
    if (!file) return;
    setPct(0);
    try {
      await upload(file, setPct);
      toast("DB를 적용했습니다. 재평가가 시작됩니다.", "ok");
      qc.invalidateQueries({ queryKey: ["/admin/trivy"] });
      qc.invalidateQueries({ queryKey: ["/admin/recheck"] });
    } catch (e) { toast((e as Error).message, "error"); }
    setPct(null);
    if (input.current) input.current.value = "";
  }

  return (
    <>
      <PageHeader title="Trivy DB" description="폐쇄망이라 취약점 DB는 인터넷 PC에서 받아 직접 올립니다. 잘못된 파일은 거부되고 기존 DB가 유지됩니다." />
      <Loading q={q} />
      {stale && <div className="alert alert-warn" role="alert">DB가 오래되었습니다. 다음 갱신 예정일({fmtDateTime(s!.next_update!)})에서 7일 넘게 지났습니다. 새 DB를 올려 주세요.</div>}
      {s && (
        <Panel title="현재 상태" meta={s.trivy_version && `Trivy ${s.trivy_version}`}>
          <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "6px 20px", margin: 0 }}>
            <dt className="muted">DB 버전</dt><dd className="num" style={{ margin: 0 }}>{s.db_version ? `v${s.db_version}` : "없음"}</dd>
            <dt className="muted">DB 갱신일</dt><dd style={{ margin: 0 }}>{s.updated_at ? fmtDateTime(s.updated_at) : "-"}</dd>
            <dt className="muted">다음 갱신 예정</dt><dd style={{ margin: 0 }}>{s.next_update ? fmtDateTime(s.next_update) : "-"}</dd>
            <dt className="muted">Java DB</dt><dd style={{ margin: 0 }}>{s.java_db ? `있음 · ${fmtDateTime(s.java_db.updated_at)}` : "없음 · 서버 스캔은 JAR/WAR/EAR 파일을 건너뜁니다"}</dd>
            <dt className="muted">스캐너</dt><dd style={{ margin: 0 }}>{(s.scanners ?? []).join(", ") || "-"}</dd>
          </dl>
        </Panel>
      )}
      {s && <ScannerSettings key={(s.scanners ?? []).join(",")} current={s.scanners ?? []} />}
      <Panel title="DB 올리기">
        <div className="admin-actions">
          <input ref={input} type="file" accept=".gz,.tgz,application/gzip" hidden onChange={(e) => pick(e.target.files?.[0])} />
          <Button variant="primary" icon="arrowRight" disabled={pct !== null} onClick={() => input.current?.click()}>파일 선택 (db.tar.gz / javadb.tar.gz)</Button>
          {pct !== null && <><div className="progress" style={{ width: 200 }} role="progressbar" aria-label="DB 업로드 진행률" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${pct}%` }} /></div><span className="num">{pct}%{pct === 100 && " · 검증 중"}</span></>}
        </div>
        <h3 style={{ margin: "18px 0 0", fontSize: 13.5 }}>인터넷 PC에서 파일 받는 방법</h3>
        <ol className="steps">
          <li>인터넷이 되는 PC에 <a href="https://oras.land" target="_blank" rel="noreferrer">oras</a>를 설치합니다.</li>
          <li>취약점 DB를 받습니다. 현재 디렉터리에 <code>db.tar.gz</code>가 생깁니다.
            <pre className="code">oras pull ghcr.io/aquasecurity/trivy-db:2</pre></li>
          <li>Java 라이브러리(jar) 검사가 필요하면 java-db도 받습니다. <code>javadb.tar.gz</code>가 생깁니다.
            <pre className="code">oras pull ghcr.io/aquasecurity/trivy-java-db:1</pre></li>
          <li>파일을 USB 등으로 옮겨 위에서 올립니다. 두 파일은 각각 따로 올립니다.</li>
        </ol>
      </Panel>
      <RecheckRuns />
    </>
  );
}
