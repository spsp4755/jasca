import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { API_BASE } from "../../api/client";
import { daysUntil, fmtDateTime } from "../../lib/format";
import { useToast } from "../../components/Toast";
import type { TrivyStatus } from "../../api/types";
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

function javaDb(v: unknown): string {
  if (!v) return "없음";
  if (typeof v === "string") return v;
  const o = v as Record<string, unknown>;
  const ver = o.version ?? o.db_version, at = o.updated_at;
  return [ver && `v${ver}`, typeof at === "string" && fmtDateTime(at)].filter(Boolean).join(" · ") || JSON.stringify(v);
}

export default function Trivy() {
  const q = useApi<TrivyStatus>("/admin/trivy");
  const qc = useQueryClient();
  const toast = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [pct, setPct] = useState<number | null>(null);
  const s = q.data;
  const stale = !!s?.next_update && daysUntil(s.next_update) < 0;

  async function pick(file?: File) {
    if (!file) return;
    setPct(0);
    try {
      await upload(file, setPct);
      toast("DB를 적용했습니다. 재검사가 시작됩니다.", "ok");
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
      {stale && <div className="alert alert-warn" role="alert">DB가 오래되었습니다. 다음 갱신 예정일({fmtDateTime(s!.next_update!)})이 지났습니다. 새 DB를 올려 주세요.</div>}
      {s && (
        <Panel title="현재 상태" meta={s.trivy_version && `Trivy ${s.trivy_version}`}>
          <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "6px 20px", margin: 0 }}>
            <dt className="muted">DB 버전</dt><dd className="num" style={{ margin: 0 }}>{s.db_version || "없음"}</dd>
            <dt className="muted">DB 갱신일</dt><dd style={{ margin: 0 }}>{s.updated_at ? fmtDateTime(s.updated_at) : "-"}</dd>
            <dt className="muted">다음 갱신 예정</dt><dd style={{ margin: 0 }}>{s.next_update ? fmtDateTime(s.next_update) : "-"}</dd>
            <dt className="muted">Java DB</dt><dd style={{ margin: 0 }}>{javaDb(s.java_db)}</dd>
            <dt className="muted">스캐너</dt><dd style={{ margin: 0 }}>{(s.scanners ?? []).join(", ") || "-"}</dd>
          </dl>
        </Panel>
      )}
      <Panel title="DB 올리기">
        <div className="admin-actions">
          <input ref={input} type="file" accept=".gz,.tgz,application/gzip" hidden onChange={(e) => pick(e.target.files?.[0])} />
          <Button variant="primary" icon="arrowRight" disabled={pct !== null} onClick={() => input.current?.click()}>파일 선택 (db.tar.gz / javadb.tar.gz)</Button>
          {pct !== null && <><div className="progress" style={{ width: 200 }} role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${pct}%` }} /></div><span className="num">{pct}%{pct === 100 && " · 검증 중"}</span></>}
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
