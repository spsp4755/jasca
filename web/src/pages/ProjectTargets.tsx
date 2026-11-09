import { Link, useNavigate } from "react-router-dom";
import { useApi } from "../api/hooks";
import type { Project, Target } from "../api/types";
import Icon from "../components/Icon";
import Table from "../components/Table";
import { TARGET_KIND_LABEL, fmtDateTime, fmtNumber, fmtRelative } from "../lib/format";
import { SummaryCell } from "./Home";
import { FirstScan } from "./ProjectFindings";

export default function ProjectTargets({ project }: { project: Project }) {
  const q = useApi<Target[] | null>(`/projects/${project.key}/targets`);
  const navigate = useNavigate();
  const rows = q.data ?? [];
  if (q.isSuccess && !rows.length) return <FirstScan project={project} />;
  return (
    <div className="panel">
      {q.isError && <div className="alert alert-danger" role="alert" style={{ margin: 12 }}><Icon name="alert" />{q.error.message}</div>}
      <Table<Target> caption="대상 목록" rows={rows} rowKey={(t) => t.id} loading={q.isPending}
        onRowClick={(t) => navigate(`/projects/${project.key}?target_id=${t.id}`)}
        columns={[
          { key: "kind", header: "종류", width: 100, render: (t) => <span className="tag tag-quiet">{TARGET_KIND_LABEL[t.kind] ?? t.kind}</span> },
          { key: "name", header: "이름", render: (t) => (
            <span className="target-name">
              <span className="mono">{t.name}</span>
              {t.recheck_excluded && <span className="tag tag-quiet" title="Harbor 대상은 재평가와 사내 Advisory 매칭에서 제외됩니다.">재평가 제외</span>}
            </span>) },
          { key: "open", header: "열린 결과", width: 90, align: "right", render: (t) => <b className={`num${t.counts.open ? "" : " muted"}`}>{fmtNumber(t.counts.open)}</b> },
          { key: "sev", header: "심각도별", width: 260, render: (t) => <SummaryCell s={t.counts} /> },
          { key: "scan", header: "마지막 스캔", width: 120, align: "right", render: (t) => <span className="muted" title={fmtDateTime(t.last_scan_at)}>{t.last_scan_at ? fmtRelative(t.last_scan_at) : "없음"}</span> },
          { key: "go", header: <span className="sr-only">스캔 기록</span>, width: 96, align: "right", render: (t) => <Link to={`/projects/${project.key}/scans?target_id=${t.id}`} className="nw">스캔 기록</Link> },
        ]} />
    </div>
  );
}
