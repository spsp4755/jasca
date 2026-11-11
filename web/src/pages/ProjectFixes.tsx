import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { qs } from "../api/client";
import { useApi } from "../api/hooks";
import type { Counts, Finding, FixGroup, FixPlan, Project, Target } from "../api/types";
import { SEVERITIES } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import SeverityBadge from "../components/SeverityBadge";
import Table from "../components/Table";
import { useToast } from "../components/Toast";
import { copyText } from "../lib/clipboard";
import { KIND_LABEL, TARGET_KIND_LABEL, fmtNumber } from "../lib/format";
import FindingDrawer from "./FindingDrawer";
import { FirstScan } from "./ProjectFindings";

const OTHER_KINDS = ["misconfig", "secret", "sast"] as const;

/** Severity counts of a group: what the upgrade resolves, or every finding when no upgrade resolves any. */
export const fixCounts = (g: FixGroup): Partial<Counts> => {
  if (g.resolves.open > 0) return g.resolves;
  const c: Record<string, number> = {};
  for (const f of g.findings) c[f.severity.toLowerCase()] = (c[f.severity.toLowerCase()] ?? 0) + 1;
  return c;
};
/** "2.17.1 이상", or the fixed versions as the scanner wrote them when they could not be compared. */
export const fixTo = (g: FixGroup) => (g.recommended ? `${g.recommended} 이상` : g.fixed_versions.join(", "));
const sevText = (c: Partial<Counts>) => SEVERITIES.flatMap((s) => { const n = c[s.toLowerCase() as keyof Counts] ?? 0; return n ? [`${s} ${n}`] : []; }).join(", ");
const lead = (plan: FixPlan, resolved: number) => `패키지 ${fmtNumber(plan.groups.length)}개를 올리면 열린 취약점 ${fmtNumber(plan.totals.open_vulns)}건 중 ${fmtNumber(resolved)}건이 해결됩니다.`;

/** One group as text for a ticket or a chat message: what to upgrade, what it resolves, where, which CVEs. */
function groupText(g: FixGroup, n?: number) {
  const fixable = g.resolves.open > 0;
  const head = `${n ? `${n}. ` : "- "}${g.package}${g.ecosystem ? ` (${g.ecosystem})` : ""} ${g.installed}${fixable ? ` → ${fixTo(g)}${g.recommended || g.fixed_versions.length < 2 ? "" : " 중 설치 계열에 맞는 버전"}` : ""}`;
  const count = fixable
    ? `해결 ${g.resolves.open}건 (${sevText(g.resolves)})${g.no_fix ? `, 아직 조치 버전 없음 ${g.no_fix}건` : ""}`
    : `조치 버전 없음 ${g.findings.length}건 (${sevText(fixCounts(g))})`;
  return [head, `   ${count}`, `   대상: ${g.targets.map((t) => t.name).join(", ")}`, `   ${[...new Set(g.findings.map((f) => f.rule_id))].join(", ")}`].join("\n");
}

function planText(project: Project, plan: FixPlan, resolved: number, target?: Target) {
  const t = plan.totals;
  const other = OTHER_KINDS.filter((k) => t.other_kinds[k] > 0).map((k) => `${KIND_LABEL[k]} ${t.other_kinds[k]}건`);
  return [
    `[${project.name}] 조치 계획${target ? ` · 대상 ${target.name}` : ""}`,
    plan.groups.length ? lead(plan, resolved) : `열린 취약점 ${t.open_vulns}건 중 버전을 올려 해결되는 것이 아직 없습니다.`,
    ...(plan.truncated ? [`(결과가 많아 심각도가 높은 ${plan.limit}건만 묶었습니다.)`] : []),
    ...plan.groups.flatMap((g, i) => ["", groupText(g, i + 1)]),
    ...(plan.no_fix_groups.length ? ["", "조치 버전이 아직 없는 패키지 (올려도 해결되지 않음: 완화하거나 예외 요청)", ...plan.no_fix_groups.map((g) => groupText(g))] : []),
    ...(other.length ? ["", `이 계획에 없는 열린 결과: ${other.join(", ")}`] : []),
  ].join("\n");
}

/** 조치 계획 tab: the project's open vulnerabilities grouped by the package upgrade that resolves them. Read-only. */
export default function ProjectFixes({ project }: { project: Project }) {
  const [sp, setSp] = useSearchParams();
  const toast = useToast();
  const k = encodeURIComponent(project.key);
  const targetId = sp.get("target_id") ?? "";
  const targets = useApi<Target[] | null>(`/projects/${k}/targets`).data ?? [];
  const q = useApi<FixPlan>(project.last_scan_at ? `/projects/${k}/fixes${qs({ target_id: targetId })}` : null);
  // the open drawer lives in the URL (?finding=<id>), as on the results tab
  const openId = Number(sp.get("finding")) || null;
  const open = useApi<Finding>(openId ? `/findings/${openId}` : null);
  const set = (key: string, v: string) => setSp((p) => {
    const n = new URLSearchParams(p);
    if (v) n.set(key, v); else n.delete(key);
    return n;
  }, { replace: true });
  if (!project.last_scan_at) return <FirstScan project={project} />;

  const plan = q.data;
  const t = plan?.totals;
  const resolved = plan?.groups.reduce((n, g) => n + g.resolves.open, 0) ?? 0;
  const list = (extra: object) => `/projects/${k}${qs({ ...extra, target_id: targetId })}`;
  const other = t ? OTHER_KINDS.filter((kind) => t.other_kinds[kind] > 0) : [];
  const copy = async (text: string, what: string) => toast((await copyText(text)) ? `${what} 복사했습니다. 티켓이나 메신저에 붙여 넣으세요.` : "복사하지 못했습니다. 브라우저의 클립보드 권한을 확인하세요.", "info");
  const row = (g: FixGroup) => (
    <FixRow key={`${g.ecosystem}|${g.package}|${g.installed}`} g={g} projectKey={project.key}
      onOpen={(id) => set("finding", String(id))} onCopy={() => copy(groupText(g), `${g.package} 조치 내용을`)} />
  );

  return (
    <div className="fixes">
      <div className="fix-bar">
        {(targets.length > 1 || targetId) && (
          <select className="input" aria-label="대상" value={targetId} onChange={(e) => set("target_id", e.target.value)}>
            <option value="">모든 대상</option>
            {targets.map((tg) => <option key={tg.id} value={tg.id}>{TARGET_KIND_LABEL[tg.kind]} · {tg.name}</option>)}
          </select>
        )}
        {plan && t!.open_vulns > 0 && (
          <Button size="sm" icon="copy" className="fix-copy" onClick={() => copy(planText(project, plan, resolved, targets.find((tg) => String(tg.id) === targetId)), "조치 계획을")}>계획 전체 복사</Button>
        )}
      </div>
      {q.isError && <div className="alert alert-danger" role="alert"><Icon name="alert" />{q.error.message}<Button size="sm" className="alert-action" onClick={() => q.refetch()}>다시 시도</Button></div>}
      {q.isPending && <div className="panel"><Table caption="불러오는 중" rows={[]} rowKey={() => 0} columns={[{ key: "x", header: "" }]} loading /></div>}
      {plan && t && (
        <>
          <section className="panel fix-summary" aria-label="요약">
            {t.open_vulns === 0 ? (
              t.inventory_targets > 0
                ? <Empty compact icon="shieldCheck" title="열린 취약점이 없습니다"
                    description={`패키지 목록이 있는 대상 ${fmtNumber(t.inventory_targets)}개의 마지막 스캔 기준입니다. 해결되거나 예외 처리된 취약점은 결과 탭에서 상태를 바꿔 볼 수 있습니다.`} />
                : <Empty compact icon="alert" title="패키지를 살펴본 스캔이 없습니다"
                    description="지금까지의 스캔에는 패키지 목록이 없어 취약점이 있는지 알 수 없습니다. 이미지나 소스·패키지를 스캔하면 여기에 조치 계획이 생깁니다."
                    action={project.my_role !== "viewer" && <Link to={`/scan?project=${k}`} className="btn btn-secondary btn-sm">스캔하기</Link>} />
            ) : plan.groups.length === 0 ? (
              <>
                <p className="fix-lead">버전을 올려 해결되는 취약점이 아직 없습니다.</p>
                <p className="muted">열린 취약점 <Link to={list({ kind: "vuln" })} className="num">{fmtNumber(t.open_vulns)}건</Link> 모두 조치 버전이 나오지 않았습니다. 아래 패키지는 완화하거나 예외를 요청하세요.</p>
              </>
            ) : (
              <p className="fix-lead">
                패키지 <b className="num">{fmtNumber(plan.groups.length)}</b>개를 올리면 열린 취약점 <Link to={list({ kind: "vuln" })} className="num">{fmtNumber(t.open_vulns)}건</Link> 중{" "}
                <Link to={list({ kind: "vuln", fixable: "true" })} className="num fix-win">{fmtNumber(resolved)}건</Link>이 해결됩니다.
              </p>
            )}
            {(t.no_fix > 0 && plan.groups.length > 0 || other.length > 0 || plan.truncated) && (
              <ul className="fix-rest">
                {t.no_fix > 0 && plan.groups.length > 0 && <li>올려도 남는 취약점: <Link to={list({ kind: "vuln", fixable: "false" })} className="num">아직 조치 버전 없음 {fmtNumber(t.no_fix)}건</Link></li>}
                {other.length > 0 && (
                  <li>이 계획이 다루지 않는 열린 결과:{" "}
                    {other.map((kind, i) => <span key={kind}>{i > 0 && " · "}<Link to={list({ kind })} className="num">{KIND_LABEL[kind]} {fmtNumber(t.other_kinds[kind])}건</Link></span>)}
                  </li>
                )}
                {plan.truncated && <li>열린 취약점이 많아 심각도가 높은 {fmtNumber(plan.limit)}건만 묶었습니다. 나머지는 결과 탭에서 보세요.</li>}
              </ul>
            )}
          </section>
          {plan.groups.length > 0 && (
            <section className="panel" aria-labelledby="h-fix">
              <div className="panel-head"><h2 id="h-fix">올릴 패키지</h2><span className="panel-meta">심각한 것부터, 많이 해결되는 순서 · 줄을 누르면 대상과 취약점이 펼쳐집니다</span></div>
              <ul className="fix-list">{plan.groups.map(row)}</ul>
            </section>
          )}
          {plan.no_fix_groups.length > 0 && (
            <section className="panel" aria-labelledby="h-nofix">
              <div className="panel-head"><h2 id="h-nofix">조치 버전이 아직 없는 패키지</h2><span className="panel-meta">{fmtNumber(plan.no_fix_groups.length)}개</span></div>
              <p className="fix-note">버전을 올려도 해결되지 않습니다. 취약한 기능을 끄거나 막아 완화하고, 그대로 둘 것이면 결과를 열어 예외를 요청하세요.</p>
              <ul className="fix-list">{plan.no_fix_groups.map(row)}</ul>
            </section>
          )}
        </>
      )}
      {openId && open.isError && (
        <div className="alert alert-warn" role="alert"><Icon name="alert" />
          {open.error.status === 404 ? `이 결과(#${openId})를 찾을 수 없습니다. 삭제되었거나 볼 권한이 없는 프로젝트의 결과입니다.` : open.error.message}
          <Button size="sm" className="alert-action" onClick={() => set("finding", "")}>닫기</Button></div>
      )}
      <FindingDrawer finding={(openId && open.data) || null} onClose={() => set("finding", "")} showProject={false} />
    </div>
  );
}

function FixRow({ g, projectKey, onOpen, onCopy }: { g: FixGroup; projectKey: string; onOpen: (id: number) => void; onCopy: () => void }) {
  const [open, setOpen] = useState(false); // the body is rendered only while open: a plan can hold thousands of findings
  const fixable = g.resolves.open > 0;
  const counts = fixCounts(g);
  return (
    <li>
      <details className="fix-item" open={open} onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary className="fix-row">
          <Icon name="chevronRight" size={16} className="icon fix-chev" />
          <span className="fix-what">
            <b className="fix-pkg">{g.package}</b>
            {g.ecosystem && <span className="tag tag-quiet">{g.ecosystem}</span>}
            <span className="mono fix-ver">{g.installed || "버전 모름"}</span>
            {fixable
              ? <><span className="fix-arrow" aria-hidden="true">→</span><span className="sr-only">에서</span><span className="mono pkg-fix">{fixTo(g)}</span>
                {!g.recommended && <span className="tag tag-quiet">비교 못 함</span>}</>
              : <span className="pkg-nofix">조치 버전 없음</span>}
          </span>
          <span className="fix-gain">
            <span className="sev-row">{SEVERITIES.map((s) => { const n = counts[s.toLowerCase() as keyof Counts] ?? 0; return n > 0 && <SeverityBadge key={s} severity={s} count={n} />; })}</span>
            <span className="num nw">{fixable ? `${fmtNumber(g.resolves.open)}건 해결` : `${fmtNumber(g.findings.length)}건`}</span>
            <span className="muted num nw">대상 {fmtNumber(g.targets.length)}개</span>
          </span>
        </summary>
        {open && (
          <div className="fix-body">
            <div className="fix-facts">
              <div>
                {fixable && !g.recommended && <p>올릴 버전을 하나로 정하지 못해 스캐너가 적은 조치 버전을 그대로 보여 줍니다(패키지 종류를 모르거나, 버전 형식을 읽지 못했거나, 설치 버전보다 높지 않은 경우).{g.fixed_versions.length > 1 && " 설치된 버전 계열에 맞는 것을 고르세요."}</p>}
                {fixable && g.no_fix > 0 && <p>이 중 <b className="num">{fmtNumber(g.no_fix)}건</b>은 아직 조치 버전이 없어 올린 뒤에도 남습니다.</p>}
                <ul className="fix-targets" aria-label="설치된 대상">
                  {g.targets.map((tg) => (
                    <li key={tg.id}>
                      <span className="tag tag-quiet">{TARGET_KIND_LABEL[tg.kind] ?? tg.kind}</span>
                      <Link to={`/projects/${encodeURIComponent(projectKey)}?target_id=${tg.id}`} className="mono break">{tg.name}</Link>
                      {tg.paths.length > 0 && <span className="mono muted break">{tg.paths.join(", ")}</span>}
                    </li>
                  ))}
                </ul>
              </div>
              <Button size="sm" icon="copy" onClick={onCopy}>복사</Button>
            </div>
            <Table dense caption={`${g.package} ${g.installed} 취약점`} rows={g.findings} rowKey={(f) => f.id} onRowClick={(f) => onOpen(f.id)} columns={[
              { key: "sev", header: "심각도", width: 108, render: (f) => <SeverityBadge severity={f.severity} /> },
              { key: "rule", header: "취약점", render: (f) => (
                <span className="rule"><Link to={`/vulns/${encodeURIComponent(f.rule_id)}`} className="mono nw">{f.rule_id}</Link>
                  {f.title && <span className="rule-title" title={f.title}>{f.title}</span>}</span>) },
              { key: "target", header: "대상", width: "24%", nowrap: true, render: (f) => <span className="mono" title={f.target}>{f.target}</span> },
              { key: "fix", header: "조치 버전", width: "22%", render: (f) => (f.fixed_version ? <span className="mono pkg-fix break">{f.fixed_version}</span> : <span className="pkg-nofix">아직 없음</span>) },
            ]} />
          </div>
        )}
      </details>
    </li>
  );
}
