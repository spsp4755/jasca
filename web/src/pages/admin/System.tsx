import { Link } from "react-router-dom";
import Button from "../../components/Button";
import Icon from "../../components/Icon";
import PageHeader from "../../components/PageHeader";
import { useApi } from "../../api/hooks";
import { fmtDateTime, fmtNumber } from "../../lib/format";
import type { NotifyChannel } from "../../api/types";
import { Loading, Panel } from "./parts";

// GET /admin/system (system.go): the rows come sorted, the ones needing attention first.
export type SysState = "ok" | "warn" | "bad";
export interface SysCheck { key: string; label: string; state: SysState; value: string; action?: string; link?: string }
export interface SystemStatus {
  version: string; started_at: string; now: string; checks: SysCheck[]; log_lines: string[];
  totals: { active_users: number; projects: number; targets: number; open_findings: number; overdue_findings: number; pending_exceptions: number };
}
export interface OpsAlerts { channel_ids: number[] }

const STATE: Record<SysState, [label: string, tone: string]> = { ok: ["정상", "ok"], warn: ["주의", "warn"], bad: ["문제", "danger"] };
const TOTALS: [keyof SystemStatus["totals"], string, string][] = [
  ["projects", "프로젝트", "개"], ["targets", "대상", "개"], ["active_users", "사용자", "명"],
  ["open_findings", "열린 결과", "건"], ["overdue_findings", "기한 지난 결과", "건"], ["pending_exceptions", "승인 대기 예외", "건"],
];

/** Checked again every minute while a page shows it. */
export const useSystemStatus = (enabled = true) => useApi<SystemStatus>(enabled ? "/admin/system" : null, { refetchInterval: 60_000, staleTime: 0 });

export default function System() {
  const q = useSystemStatus();
  const d = q.data;
  const bad = d?.checks.filter((c) => c.state === "bad") ?? [];
  const warn = d?.checks.filter((c) => c.state === "warn") ?? [];
  const worst: SysState = bad.length ? "bad" : warn.length ? "warn" : "ok";
  return (
    <>
      <PageHeader title="시스템 상태" description="JASCA가 제대로 돌고 있는지 한 화면에서 확인합니다. 열어 두면 1분마다 다시 확인합니다."
        actions={<>
          {d && <span className="page-meta">{fmtDateTime(d.now)} 확인</span>}
          <Button loading={q.isFetching} onClick={() => q.refetch()}>다시 확인</Button>
        </>} />
      <Loading q={q} />
      {d && (
        <>
          <div className={`sys-summary sys-${worst}`} role="status">
            <Icon name={worst === "ok" ? "shieldCheck" : "alert"} size={22} />
            <div>
              <b>{worst === "ok" ? "모든 항목이 정상입니다" : [bad.length && `문제 ${bad.length}건`, warn.length && `주의 ${warn.length}건`].filter(Boolean).join(" · ")}</b>
              <p>{worst === "ok" ? "지금 조치할 것이 없습니다." : `${[...bad, ...warn].map((c) => c.label).join(", ")} — 아래 안내대로 조치하세요.`}</p>
            </div>
          </div>
          <div className="detail-grid sys-grid">
            <div className="detail-main">
              <section className="panel" aria-labelledby="h-checks">
                <div className="panel-head"><h2 id="h-checks">점검 항목</h2><span className="panel-meta">조치가 필요한 항목이 위에 옵니다</span></div>
                <ul className="sys-list">
                  {d.checks.map((c) => (
                    <li key={c.key} className={`sys-row sys-row-${c.state}`}>
                      <span className={`status status-${STATE[c.state][1]} sys-state`}><span className="status-dot" aria-hidden="true" />{STATE[c.state][0]}</span>
                      <span className="sys-label">{c.label}</span>
                      <div className="sys-text">
                        <p className="sys-value">{c.value}</p>
                        {c.action && <p className="sys-action">{c.action}</p>}
                      </div>
                      {c.link ? <Link to={c.link} className="btn btn-secondary btn-sm sys-link" aria-label={`${c.label} 화면 열기`}>열기</Link> : <span className="sys-link" />}
                    </li>
                  ))}
                </ul>
              </section>
              <Panel title="최근 서버 로그" meta="최근 24시간의 경고·오류 중 마지막 5건">
                {d.log_lines.length === 0
                  ? <p className="muted" style={{ margin: 0 }}>최근 24시간 동안 서버가 남긴 경고·오류가 없습니다.</p>
                  : <pre className="code sys-log" tabIndex={0} aria-label="최근 서버 로그">{d.log_lines.join("\n")}</pre>}
              </Panel>
            </div>
            <aside className="detail-side">
              <OpsAlertTargets />
              <Panel title="규모">
                <dl className="kv kv-tight sys-kv">
                  {TOTALS.map(([k, label, unit]) => <div className="kv-row" key={k}><dt>{label}</dt><dd className="num">{fmtNumber(d.totals[k])}{unit}</dd></div>)}
                  <div className="kv-row"><dt>버전</dt><dd className="mono">{d.version}</dd></div>
                  <div className="kv-row"><dt>시작</dt><dd>{fmtDateTime(d.started_at)}</dd></div>
                </dl>
              </Panel>
            </aside>
          </div>
        </>
      )}
    </>
  );
}

/** Who is told when a row turns bad: the channels picked in 관리 → 알림 채널. */
function OpsAlertTargets() {
  const ops = useApi<OpsAlerts>("/admin/ops-alerts");
  const channels = useApi<NotifyChannel[]>("/admin/channels");
  const picked = (channels.data ?? []).filter((c) => ops.data?.channel_ids.includes(c.id));
  const on = picked.filter((c) => c.enabled);
  return (
    <Panel title="운영 알림">
      {ops.error || channels.error ? <p className="muted" style={{ margin: 0 }}>알림 설정을 불러오지 못했습니다.</p>
        : !ops.data || !channels.data ? <div className="skeleton" style={{ height: 48 }} />
          : on.length === 0 ? (
            <p className="sys-noalert"><Icon name="alert" /><span>받는 채널이 없습니다. 문제가 생겨도 이 화면을 열어 봐야 알 수 있습니다.</span></p>
          ) : (
            <p style={{ margin: 0 }}>문제가 생기면 <b>{on.map((c) => c.name).join(", ")}</b> 채널로 한 번 알립니다.</p>
          )}
      <p className="side-note" style={{ marginTop: 8 }}><Link to="/admin/channels">알림 채널</Link>에서 받을 채널을 고릅니다.</p>
    </Panel>
  );
}

/** Home, for administrators: one line when a row is bad. `skip` leaves out what the shell already announces. */
export function SystemNotice({ skip = [] }: { skip?: string[] }) {
  const bad = (useSystemStatus().data?.checks ?? []).filter((c) => c.state === "bad" && !skip.includes(c.key));
  if (!bad.length) return null;
  return (
    <div className="alert alert-danger" role="status" style={{ marginBottom: 16 }}><Icon name="alert" />
      <span>시스템 상태에 문제가 {bad.length}건 있습니다({bad.map((c) => c.label).join(", ")}). <Link to="/admin/system">시스템 상태 보기</Link></span>
    </div>
  );
}
