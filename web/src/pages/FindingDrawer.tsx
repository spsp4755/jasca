import { useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { isSecurity, useApi, useMe } from "../api/hooks";
import type { ExceptionCreate, ExceptionResolution, ExceptionScope, Finding, Project, ProjectRole } from "../api/types";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Field from "../components/Field";
import Icon from "../components/Icon";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import { useToast } from "../components/Toast";
import { KIND_LABEL, ORIGIN_LABEL, RESOLUTION_LABEL, TARGET_KIND_LABEL, dateInput, endOfDayISO, fmtDateTime, fmtDaysAgo, fmtDue } from "../lib/format";
import { Triage, canTriage } from "./FindingTriage";

const DETAIL_LABEL: Record<string, string> = {
  message: "메시지", description: "설명", resolution: "조치 방법", resource: "리소스", namespace: "네임스페이스",
  category: "분류", start_line: "시작 줄", end_line: "끝 줄", snippet: "코드", redacted_match_sha256: "일치 값 해시",
};
const HIDDEN = new Set(["partial_fingerprints"]);
const HASHES = new Set(["redacted_match_sha256"]); // identifiers nobody acts on: shown last, under 출처

const line = (v: unknown) => (typeof v === "number" && v > 0 ? v : 0);
/** "path:12" or "path:12-15": where a secret, misconfiguration or code finding sits. */
export const whereOf = (f: { location: string; details?: Record<string, unknown> }) => {
  const a = line(f.details?.start_line), b = line(f.details?.end_line);
  return f.location + (f.location && a ? `:${a}${b > a ? `-${b}` : ""}` : "");
};
/** Dotted numbers only ("1.2.6", "v4.17.19"). Epochs, suffixes and the like are for the server's internal/versions, not for here. */
const nums = (v: string) => (/^v?\d+(\.\d+)*$/.test(v) ? v.replace(/^v/, "").split(".").map(Number) : null);
const cmpNums = (a: number[], b: number[]) => { for (let i = 0; i < Math.max(a.length, b.length); i++) { const d = (a[i] ?? 0) - (b[i] ?? 0); if (d) return d; } return 0; };
/**
 * Which version to move to. Scanners list one fixed version per release line ("1.2.6, 0.2.4") and sometimes write a
 * range (">=4.17.19"). With several, the one for the installed line is named only when plain numbers settle it: same
 * major version, the lowest one above the installed version. Otherwise all are listed for the reader to choose.
 */
function upgradeText(pkg: string, installed: string, fixed: string) {
  const fixes = fixed.split(",").map((v) => v.trim().replace(/^[<>=~^\s]+/, "")).filter(Boolean);
  const cur = nums(installed), all = fixes.map(nums);
  const mine = cur && all.every((n) => n) ? (all as number[][]).filter((n) => n[0] === cur[0] && cmpNums(n, cur) > 0).sort(cmpNums)[0] : undefined;
  const one = fixes.length === 1 ? fixes[0] : mine?.join(".");
  return one ? `${pkg} 패키지를 ${one} 버전 이상으로 올리세요.` : `${pkg} 패키지를 다음 중 설치된 버전 계열에 맞는 버전으로 올리세요: ${fixes.join(", ")}`;
}
/** One sentence saying what to do, from what the finding already carries. Fixed wording around the names avoids Korean particle errors. */
function todo(f: Finding) {
  const where = whereOf(f);
  if (f.kind === "vuln") {
    return f.fixed_version ? upgradeText(f.pkg_name, f.pkg_version, f.fixed_version)
      : "아직 조치 버전이 없습니다. 위험을 감수할지 정해 예외를 요청하거나 패키지 교체를 검토하세요.";
  }
  if (f.kind === "secret") return `${where || "해당 파일"}의 비밀값을 폐기(재발급)하고 코드에서 지우세요.`;
  return `${where ? `${where}에서 ` : ""}"${f.title || f.rule_id}" 규칙에 걸린 곳을 고치세요.`;
}

const isMember = (role?: ProjectRole | "") => role === "member" || role === "owner";
/**
 * Who may ask for an exception on a finding, as POST /exceptions decides it: a member or owner of its project in any
 * scope; a security user who is not a member only company-wide, which exists only for a vulnerability.
 */
export const canAskFor = (f: Finding, role: ProjectRole | "" | undefined, security: boolean) => isMember(role) || (security && f.kind === "vuln");

/** Side panel with everything known about one finding. */
export default function FindingDrawer({ finding: f, onClose, showProject = true }: { finding: Finding | null; onClose: () => void; showProject?: boolean }) {
  const [ask, setAsk] = useState(false);
  const me = useMe();
  const role = useApi<Project[]>("/projects").data?.find((p) => p.key === f?.project_key)?.my_role;
  const canAsk = !!f && canAskFor(f, role, isSecurity(me.data)); // viewers would only get a 403
  // asked again on every open, since the row may be older than a request just sent or an assignment just made:
  // a request already waiting for a decision, the assignee and the deadline with the policy days behind it
  const detail = useApi<Finding>(f ? `/findings/${f.id}` : null, { staleTime: 0 }).data;
  const pending = detail?.pending_exception_id;
  const now = f && detail?.id === f.id ? detail : f;
  const late = now?.status === "open" && now.due_at ? fmtDue(now.due_at) : null;
  const waiting = f?.status === "open" && pending ? <Link to={`/exceptions?id=${pending}`}>예외 승인 대기 중</Link> : null;
  // start/end lines are part of 위치 when there is a file to attach them to
  const all = f ? Object.entries(f.details ?? {}).filter(([k, v]) => !HIDDEN.has(k) && v !== "" && v !== null && v !== 0
    && !(f.location && (k === "start_line" || k === "end_line"))) : [];
  const details = all.filter(([k]) => !HASHES.has(k)), hashes = all.filter(([k]) => HASHES.has(k));
  return (
    <>
      <Dialog open={!!f && !ask} onClose={onClose} size="drawer"
        title={f && <span className="drawer-title"><SeverityBadge severity={f.severity} /><span className="mono">{f.rule_id}</span></span>}
        description={f?.title || undefined}
        footer={f && (
          <>
            {f.status === "open" && canAsk && (waiting
              ? <Link className="btn btn-secondary" to={`/exceptions?id=${pending}`}><Icon name="shield" />예외 승인 대기 중</Link>
              : <Button icon="shield" onClick={() => setAsk(true)}>예외 요청</Button>)}
            {f.kind === "vuln" && <Link className="btn btn-primary" to={`/vulns/${encodeURIComponent(f.rule_id)}`}>취약점 상세<Icon name="arrowRight" size={14} /></Link>}
          </>
        )}>
        {f && (
          <>
            {f.status === "open" && <p className="drawer-todo"><Icon name="arrowRight" size={15} /><span><b>할 일</b> {todo(f)}
              {/* this sentence looks at one vulnerability; the plan names the version that clears every one of the package */}
              {f.kind === "vuln" && f.fixed_version && <> <Link to={`/projects/${encodeURIComponent(f.project_key)}/fixes`}>이 패키지의 다른 취약점까지 한 번에 해결하는 버전은 조치 계획에서 봅니다.</Link></>}
              {late?.over && <b className="todo-late"> 조치 기한이 {late.days < 0 ? `${-late.days}일` : "오늘"} 지났습니다.</b>}</span></p>}
            {now && <Triage f={now} canEdit={canTriage(role, isSecurity(me.data))} />}
            <dl className="kv">
              <Row label="상태"><StatusBadge status={f.status} />{waiting && <> · {waiting}</>}{f.reopened_count > 0 && <span className="muted"> · 다시 열림 {f.reopened_count}회</span>}</Row>
              {f.exception_id && <Row label="예외"><Link to={`/exceptions?id=${f.exception_id}`}>예외 #{f.exception_id}</Link></Row>}
              {f.pkg_name && <Row label="패키지"><b>{f.pkg_name}</b> <span className="mono">{f.pkg_version}</span></Row>}
              {f.pkg_name && <Row label="조치 버전">{f.fixed_version ? <span className="mono pkg-fix">{f.fixed_version}</span> : <span className="muted">아직 없음</span>}</Row>}
              {f.pkg_path && <Row label="경로"><span className="mono break">{f.pkg_path}</span></Row>}
              {f.location && <Row label="위치"><span className="mono break">{whereOf(f)}</span></Row>}
              {showProject && <Row label="프로젝트"><Link to={`/projects/${encodeURIComponent(f.project_key)}`}>{f.project_key}</Link></Row>}
              <Row label="대상">{TARGET_KIND_LABEL[f.target_kind] ?? f.target_kind} · <span className="mono break">{f.target_name}</span></Row>
              <Row label="처음 발견">{fmtDateTime(f.first_seen_at)} <span className="muted">({fmtDaysAgo(f.first_seen_at)})</span></Row>
              <Row label="마지막 확인">{fmtDateTime(f.last_seen_at)}</Row>
              {f.fixed_at && <Row label="해결">{fmtDateTime(f.fixed_at)}</Row>}
            </dl>
            {details.length > 0 && (
              <section className="drawer-sec">
                <h3>세부 정보</h3>
                <dl className="kv">
                  {details.map(([k, v]) => (
                    <Row key={k} label={DETAIL_LABEL[k] ?? k}>
                      <span className={k === "snippet" ? "mono break" : "pre"}>{typeof v === "string" ? v : JSON.stringify(v)}</span>
                    </Row>
                  ))}
                </dl>
              </section>
            )}
            <section className="drawer-sec">
              <h3>출처</h3>
              <dl className="kv">
                <Row label="종류">{KIND_LABEL[f.kind] ?? f.kind}</Row>
                <Row label="찾은 방법">{ORIGIN_LABEL[f.origin] ?? f.origin} · <span className="mono">{f.tool}</span></Row>
                {hashes.map(([k, v]) => <Row key={k} label={DETAIL_LABEL[k] ?? k}><span className="mono break muted">{String(v)}</span></Row>)}
              </dl>
            </section>
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
 * Asks for an exception. Scope "finding" covers the chosen findings; when they are all one vulnerability the user may
 * instead cover that vulnerability in their project(s) (project_vuln) or, as a security user, everywhere (global_vuln).
 * POST /exceptions takes one project per request, so a selection spanning projects is sent as one request per project.
 */
export function ExceptionRequestDialog({ open, findings, onClose, onDone }: {
  open: boolean; findings: Finding[]; onClose: () => void; onDone?: () => void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const me = useMe();
  const [resolution, setResolution] = useState<ExceptionResolution>("accepted");
  const [scope, setScope] = useState<ExceptionScope>("finding");
  const projects = useApi<Project[]>("/projects").data;
  const rules = new Set(findings.map((f) => f.rule_id));
  const vulnID = rules.size === 1 && findings.every((f) => f.kind === "vuln") ? findings[0].rule_id : "";
  // only what POST /exceptions will take: the project scopes need a member, the company-wide one a security user
  const member = findings.every((f) => isMember(projects?.find((p) => p.key === f.project_key)?.my_role));
  const scopes: ExceptionScope[] = [...(member ? ["finding" as const] : []), ...(member && vulnID ? ["project_vuln" as const] : []),
    ...(vulnID && isSecurity(me.data) ? ["global_vuln" as const] : [])];
  const sc = scopes.includes(scope) ? scope : scopes[0];
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState(dateInput(90));
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const byProject = new Map<string, number[]>();
  for (const f of findings) byProject.set(f.project_key, [...(byProject.get(f.project_key) ?? []), f.id]);
  const reasonOK = [...reason.trim()].length >= 5; // characters, as the API counts them
  const reasonErr = touched && !reasonOK ? "사유를 5자 이상 적어 주세요. 승인자가 판단할 근거가 됩니다." : undefined;
  const dateErr = !expires || expires < dateInput(1) || expires > dateInput(364) ? "내일부터 1년 안의 날짜를 고르세요." : undefined;
  const close = () => { onClose(); setReason(""); setTouched(false); setErr(""); setResolution("accepted"); setScope("finding"); setExpires(dateInput(90)); };
  const submit = async () => {
    setTouched(true);
    if (!sc || !reasonOK || dateErr) return;
    setBusy(true); setErr("");
    const common = { resolution, reason: reason.trim(), expires_at: endOfDayISO(expires) };
    const bodies: [string, ExceptionCreate][] = sc === "global_vuln" ? [["전체", { scope: sc, vuln_id: vulnID, ...common }]]
      : [...byProject].flatMap(([project_key, ids]): [string, ExceptionCreate][] => sc === "finding"
        // the API takes at most 200 findings per request
        ? Array.from({ length: Math.ceil(ids.length / 200) }, (_, i) => [project_key, { scope: sc, project_key, finding_ids: ids.slice(i * 200, i * 200 + 200), ...common }])
        : [[project_key, { scope: sc, project_key, vuln_id: vulnID, ...common }]]);
    const results = await Promise.allSettled(bodies.map(([, b]) => api.post("/exceptions", b)));
    setBusy(false);
    qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("/exceptions") });
    const failed = results.flatMap((r, i) => (r.status === "rejected" ? [`${bodies[i][0]}: ${(r.reason as Error).message}`] : []));
    if (failed.length === results.length) { setErr(failed.join("\n")); return; }
    toast(failed.length ? `일부 프로젝트만 요청했습니다. 실패: ${failed.join(", ")}` : "예외를 요청했습니다. 보안 담당자가 승인하면 상태가 바뀝니다.", failed.length ? "error" : "ok");
    close();
    onDone?.();
  };
  return (
    <Dialog open={open} onClose={close} title="예외 요청"
      description={`${findings.length}건${byProject.size > 1 ? ` (프로젝트 ${byProject.size}개)` : ""}을 보안 담당자 승인 후 예외로 처리합니다. 만료되면 다시 열립니다.`}
      footer={<><Button onClick={close}>취소</Button><Button variant="primary" loading={busy} disabled={!sc} onClick={submit}>요청 보내기</Button></>}>
      {open && !sc && <div className="alert alert-warn" role="alert" style={{ margin: 0 }}><Icon name="alert" />고른 결과 중에 내가 멤버가 아닌 프로젝트의 것이 있어 요청할 수 없습니다.{isSecurity(me.data) && " 같은 취약점 하나의 결과만 고르면 전사 범위로 요청할 수 있습니다."}</div>}
      {(scopes.length > 1 || sc === "global_vuln") && (
        <fieldset className="field">
          <legend className="field-label">범위</legend>
          <div className="choice-list">
            {scopes.map((s) => (
              <label key={s} className="choice">
                <input type="radio" name="scope" checked={sc === s} onChange={() => setScope(s)} />
                <span><b>{{ finding: "고른 결과만", project_vuln: "이 프로젝트의 같은 취약점 전체", global_vuln: "모든 프로젝트의 같은 취약점" }[s]}</b>
                  <span className="muted">{{ finding: `${findings.length}건에만 적용합니다.`,
                    project_vuln: `${vulnID}: 앞으로 이 프로젝트에서 새로 발견되는 것도 포함합니다.`,
                    global_vuln: `${vulnID}: 모든 프로젝트에 적용합니다(보안 담당자 전용).` }[s]}</span></span>
              </label>
            ))}
          </div>
          {!member && <p className="field-hint">이 프로젝트의 멤버가 아니어서 전사 범위로만 요청할 수 있습니다.</p>}
        </fieldset>
      )}
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
