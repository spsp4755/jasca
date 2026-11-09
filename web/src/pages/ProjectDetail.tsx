import { Link, useNavigate, useParams } from "react-router-dom";
import { useApi } from "../api/hooks";
import type { Counts, ExceptionItem, Project } from "../api/types";
import { SEVERITIES } from "../api/types";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import Table from "../components/Table";
import Tabs from "../components/Tabs";
import { RESOLUTION_LABEL, ROLE_LABEL, SCOPE_LABEL, SEVERITY_LABEL, daysUntil, fmtDate, fmtDateTime, fmtNumber, fmtRelative } from "../lib/format";
import ProjectFindings from "./ProjectFindings";
import ProjectScans from "./ProjectScans";
import ProjectSettings from "./ProjectSettings";
import ProjectTargets from "./ProjectTargets";

const TABS = ["results", "targets", "scans", "exceptions", "settings"] as const;
type Tab = (typeof TABS)[number];

export default function ProjectDetail() {
  const { key = "", "*": rest = "" } = useParams();
  const navigate = useNavigate();
  const q = useApi<Project>(`/projects/${encodeURIComponent(key)}`);
  const seg = rest.split("/")[0];
  const tab: Tab = (TABS as readonly string[]).includes(seg) ? (seg as Tab) : "results";
  const p = q.data;

  if (q.isError) {
    return (
      <>
        <PageHeader title="프로젝트" crumbs={[{ label: "프로젝트", to: "/projects" }, { label: key }]} />
        <div className="panel">
          <Empty icon={q.error.status === 404 ? "folder" : "alert"} title={q.error.status === 404 ? "프로젝트를 찾을 수 없습니다" : "프로젝트를 불러오지 못했습니다"}
            description={q.error.status === 404 ? "키가 틀렸거나, 삭제되었거나, 멤버가 아닌 프로젝트입니다. 소유자에게 멤버 추가를 요청하세요." : q.error.message}
            action={<Link to="/projects" className="btn btn-secondary btn-sm">프로젝트 목록</Link>} />
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader title={p?.name ?? key} crumbs={[{ label: "프로젝트", to: "/projects" }, { label: p?.name ?? key }]}
        description={p && (
          <span className="proj-meta">
            <span className="mono">{p.key}</span>
            {p.my_role && <span className={`tag${p.my_role === "owner" ? "" : " tag-quiet"}`}>{ROLE_LABEL[p.my_role]}</span>}
            <span title={fmtDateTime(p.last_scan_at)}>마지막 스캔 {p.last_scan_at ? fmtRelative(p.last_scan_at) : "없음"}</span>
            {p.description && <span className="proj-desc">{p.description}</span>}
          </span>
        )}
        actions={<Link to={`/scan?project=${encodeURIComponent(key)}`} className="btn btn-primary"><Icon name="scan" />스캔하기</Link>} />
      {p && <CountsStrip c={p.counts} projectKey={p.key} />}
      <Tabs label="프로젝트 화면" value={tab} onChange={(id) => navigate(`/projects/${encodeURIComponent(key)}${id === "results" ? "" : `/${id}`}`)}
        tabs={[
          { id: "results", label: "결과", count: p?.counts.open },
          { id: "targets", label: "대상" },
          { id: "scans", label: "스캔 기록" },
          { id: "exceptions", label: "예외" },
          { id: "settings", label: "설정" },
        ]} />
      <div role="tabpanel" id={`tabpanel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {!p ? <div className="panel"><Table caption="불러오는 중" rows={[]} rowKey={() => 0} columns={[{ key: "x", header: "" }]} loading /></div>
          : tab === "results" ? <ProjectFindings project={p} />
          : tab === "targets" ? <ProjectTargets project={p} />
          : tab === "scans" ? <ProjectScans project={p} />
          : tab === "exceptions" ? <ProjectExceptions project={p} />
          : <ProjectSettings project={p} />}
      </div>
    </>
  );
}

function CountsStrip({ c, projectKey }: { c: Counts; projectKey: string }) {
  return (
    <ul className="counts-strip" aria-label="열린 결과 심각도별">
      {SEVERITIES.map((s) => {
        const n = c[s.toLowerCase() as keyof Counts];
        return (
          <li key={s}>
            <Link to={`/projects/${projectKey}?severity=${s}`} className={`count-chip${n ? "" : " is-zero"}`}>
              <span className={`sev-dot dot-${s.toLowerCase()}`} aria-hidden="true" />{SEVERITY_LABEL[s]}<b className="num">{fmtNumber(n)}</b>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

/** Read-only list; approving and revoking happen on the 예외 page. GET /exceptions may answer a list or {items}. */
function ProjectExceptions({ project }: { project: Project }) {
  const q = useApi<ExceptionItem[] | { items: ExceptionItem[] } | null>(`/exceptions?project=${encodeURIComponent(project.key)}`);
  const rows = Array.isArray(q.data) ? q.data : q.data?.items ?? [];
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>이 프로젝트의 예외</h2>
        <Link to={`/exceptions?project=${encodeURIComponent(project.key)}`} className="panel-link">예외 화면에서 관리 <Icon name="chevronRight" size={14} /></Link>
      </div>
      {q.isError && <div className="alert alert-danger" role="alert" style={{ margin: "0 18px 12px" }}><Icon name="alert" />{q.error.message}</div>}
      <Table<ExceptionItem> caption="예외 목록" rows={rows} rowKey={(x) => x.id} loading={q.isPending} dense
        empty={<Empty compact icon="shield" title="예외가 없습니다" description="결과 탭에서 결과를 골라 '예외 요청'을 누르면 보안 담당자 승인 후 위험 수용이나 오탐으로 처리됩니다." />}
        columns={[
          { key: "what", header: "대상", render: (x) => (x.vuln_id
            ? <Link className="mono" to={`/vulns/${encodeURIComponent(x.vuln_id)}`}>{x.vuln_id}</Link>
            : <span className="muted">결과 #{x.finding_id}</span>) },
          { key: "scope", header: "범위", width: 110, render: (x) => <span className="tag tag-quiet">{SCOPE_LABEL[x.scope] ?? x.scope}</span> },
          { key: "res", header: "처리", width: 90, render: (x) => RESOLUTION_LABEL[x.resolution] ?? x.resolution },
          { key: "reason", header: "사유", render: (x) => <span className="clamp" title={x.reason}>{x.reason}</span> },
          { key: "status", header: "상태", width: 100, render: (x) => <StatusBadge status={x.status} /> },
          { key: "exp", header: "만료", width: 120, align: "right", render: (x) => (
            <span title={fmtDate(x.expires_at)} className={x.status === "approved" && daysUntil(x.expires_at) <= 7 ? "due due-soon" : "muted"}>
              {x.status === "approved" ? `D-${Math.max(0, daysUntil(x.expires_at))}` : fmtDate(x.expires_at)}
            </span>) },
        ]} />
    </div>
  );
}
