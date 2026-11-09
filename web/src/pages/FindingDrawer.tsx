import { useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { ExceptionCreate, ExceptionResolution, Finding } from "../api/types";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Field from "../components/Field";
import Icon from "../components/Icon";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import { useToast } from "../components/Toast";
import { KIND_LABEL, ORIGIN_LABEL, RESOLUTION_LABEL, TARGET_KIND_LABEL, dateInput, daysSince, endOfDayISO, fmtDateTime } from "../lib/format";

const DETAIL_LABEL: Record<string, string> = {
  message: "메시지", description: "설명", resolution: "조치 방법", resource: "리소스", namespace: "네임스페이스",
  category: "분류", start_line: "시작 줄", end_line: "끝 줄", snippet: "코드", redacted_match_sha256: "일치 값 해시",
};
const HIDDEN = new Set(["partial_fingerprints"]);

/** Side panel with everything known about one finding. */
export default function FindingDrawer({ finding: f, onClose, showProject = true }: { finding: Finding | null; onClose: () => void; showProject?: boolean }) {
  const [ask, setAsk] = useState(false);
  const details = f ? Object.entries(f.details ?? {}).filter(([k, v]) => !HIDDEN.has(k) && v !== "" && v !== null && v !== 0) : [];
  return (
    <>
      <Dialog open={!!f && !ask} onClose={onClose} size="drawer"
        title={f && <span className="drawer-title"><SeverityBadge severity={f.severity} /><span className="mono">{f.rule_id}</span></span>}
        description={f?.title || undefined}
        footer={f && (
          <>
            {f.status === "open" && <Button icon="shield" onClick={() => setAsk(true)}>예외 요청</Button>}
            {f.kind === "vuln" && <Link className="btn btn-primary" to={`/vulns/${encodeURIComponent(f.rule_id)}`}>취약점 상세<Icon name="arrowRight" size={14} /></Link>}
          </>
        )}>
        {f && (
          <>
            <dl className="kv">
              <Row label="상태"><StatusBadge status={f.status} />{f.reopened_count > 0 && <span className="muted"> · 다시 열림 {f.reopened_count}회</span>}</Row>
              {f.exception_id && <Row label="예외"><Link to={`/exceptions?id=${f.exception_id}`}>예외 #{f.exception_id}</Link></Row>}
              <Row label="종류">{KIND_LABEL[f.kind] ?? f.kind} · <span className="muted">{f.tool} · {ORIGIN_LABEL[f.origin] ?? f.origin}</span></Row>
              {f.pkg_name && <Row label="패키지"><b>{f.pkg_name}</b> <span className="mono">{f.pkg_version}</span></Row>}
              {f.pkg_name && <Row label="조치 버전">{f.fixed_version ? <span className="mono pkg-fix">{f.fixed_version}</span> : <span className="muted">아직 없음</span>}</Row>}
              {f.pkg_path && <Row label="경로"><span className="mono break">{f.pkg_path}</span></Row>}
              {f.location && <Row label="위치"><span className="mono break">{f.location}</span></Row>}
              {showProject && <Row label="프로젝트"><Link to={`/projects/${encodeURIComponent(f.project_key)}`}>{f.project_key}</Link></Row>}
              <Row label="대상">{TARGET_KIND_LABEL[f.target_kind] ?? f.target_kind} · <span className="mono break">{f.target_name}</span></Row>
              <Row label="처음 발견">{fmtDateTime(f.first_seen_at)} <span className="muted">({daysSince(f.first_seen_at)}일 전)</span></Row>
              <Row label="마지막 확인">{fmtDateTime(f.last_seen_at)}</Row>
              {f.fixed_at && <Row label="해결">{fmtDateTime(f.fixed_at)}</Row>}
            </dl>
            {details.length > 0 && (
              <section className="drawer-sec">
                <h3>세부 정보</h3>
                <dl className="kv">
                  {details.map(([k, v]) => (
                    <Row key={k} label={DETAIL_LABEL[k] ?? k}>
                      <span className={k === "snippet" || k === "redacted_match_sha256" ? "mono break" : "pre"}>{typeof v === "string" ? v : JSON.stringify(v)}</span>
                    </Row>
                  ))}
                </dl>
              </section>
            )}
          </>
        )}
      </Dialog>
      <ExceptionRequestDialog open={ask} findings={f ? [f] : []} onClose={() => setAsk(false)} onDone={onClose} />
    </>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return <div className="kv-row"><dt>{label}</dt><dd>{children}</dd></div>;
}

/**
 * Asks for a finding-scope exception. POST /exceptions takes one project per request, so a selection spanning projects
 * is sent as one request per project.
 */
export function ExceptionRequestDialog({ open, findings, onClose, onDone }: {
  open: boolean; findings: Finding[]; onClose: () => void; onDone?: () => void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const [resolution, setResolution] = useState<ExceptionResolution>("accepted");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState(dateInput(90));
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const byProject = new Map<string, number[]>();
  for (const f of findings) byProject.set(f.project_key, [...(byProject.get(f.project_key) ?? []), f.id]);
  const reasonErr = touched && reason.trim().length < 5 ? "사유를 5자 이상 적어 주세요. 승인자가 판단할 근거가 됩니다." : undefined;
  const dateErr = !expires || expires < dateInput(1) || expires > dateInput(364) ? "내일부터 1년 안의 날짜를 고르세요." : undefined;
  const close = () => { onClose(); setReason(""); setTouched(false); setErr(""); setResolution("accepted"); setExpires(dateInput(90)); };
  const submit = async () => {
    setTouched(true);
    if (reason.trim().length < 5 || dateErr) return;
    setBusy(true); setErr("");
    const results = await Promise.allSettled([...byProject].map(([project_key, finding_ids]) => api.post("/exceptions", {
      scope: "finding", project_key, finding_ids, resolution, reason: reason.trim(), expires_at: endOfDayISO(expires),
    } satisfies ExceptionCreate)));
    setBusy(false);
    qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("/exceptions") });
    const failed = results.flatMap((r, i) => (r.status === "rejected" ? [`${[...byProject.keys()][i]}: ${(r.reason as Error).message}`] : []));
    if (failed.length === results.length) { setErr(failed.join("\n")); return; }
    toast(failed.length ? `일부 프로젝트만 요청했습니다. 실패: ${failed.join(", ")}` : "예외를 요청했습니다. 보안 담당자가 승인하면 상태가 바뀝니다.", failed.length ? "error" : "ok");
    close();
    onDone?.();
  };
  return (
    <Dialog open={open} onClose={close} title="예외 요청"
      description={`${findings.length}건${byProject.size > 1 ? ` (프로젝트 ${byProject.size}개)` : ""}을 보안 담당자 승인 후 예외로 처리합니다. 만료되면 다시 열립니다.`}
      footer={<><Button onClick={close}>취소</Button><Button variant="primary" loading={busy} onClick={submit}>요청 보내기</Button></>}>
      <fieldset className="field">
        <legend className="field-label">처리</legend>
        <div className="choice-list choice-row">
          {(["accepted", "false_positive"] as const).map((r) => (
            <label key={r} className="choice">
              <input type="radio" name="resolution" checked={resolution === r} onChange={() => setResolution(r)} />
              <span><b>{RESOLUTION_LABEL[r]}</b><span className="muted">{r === "accepted" ? "위험을 알고 당분간 둡니다." : "실제로는 해당하지 않습니다."}</span></span>
            </label>
          ))}
        </div>
      </fieldset>
      <Field label="사유" required error={reasonErr} hint={reasonErr ? undefined : "예: 내부망 전용 서비스로 해당 기능을 쓰지 않음. 다음 배포(12월)에 업그레이드 예정."}>
        <textarea className="input" rows={4} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} onBlur={() => setTouched(true)} />
      </Field>
      <Field label="만료일" required error={dateErr} hint={dateErr ? undefined : "최대 1년. 만료 7일 전에 알림이 갑니다."}>
        <input className="input" type="date" value={expires} min={dateInput(1)} max={dateInput(364)} onChange={(e) => setExpires(e.target.value)} />
      </Field>
      {err && <div className="alert alert-danger pre" role="alert" style={{ margin: 0 }}><Icon name="alert" />{err}</div>}
    </Dialog>
  );
}
