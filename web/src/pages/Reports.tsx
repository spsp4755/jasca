import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import Table, { type Column } from "../components/Table";
import Empty from "../components/Empty";
import SeverityBadge from "../components/SeverityBadge";
import { useApi } from "../api/hooks";
import { fmtDate, fmtNumber } from "../lib/format";
import type { Project } from "../api/types";

export default function Reports() {
  const q = useApi<Project[]>("/projects");
  const cols: Column<Project>[] = [
    { key: "name", header: "프로젝트", render: (p) => <Link to={`/reports/${encodeURIComponent(p.key)}`}>{p.name}</Link> },
    { key: "key", header: "키", mono: true, render: (p) => p.key },
    { key: "c", header: "열린 결과", render: (p) => <span className="row-gap">
      <SeverityBadge severity="CRITICAL" compact count={p.counts.critical} /><SeverityBadge severity="HIGH" compact count={p.counts.high} />
      <span className="muted num">총 {fmtNumber(p.counts.open)}</span></span> },
    { key: "last", header: "마지막 스캔", nowrap: true, render: (p) => fmtDate(p.last_scan_at) },
  ];
  return (
    <>
      <PageHeader title="보고서" description="프로젝트를 고르면 인쇄할 수 있는 현황 보고서와 AI 요약 보고서를 볼 수 있습니다." />
      {q.error && <div className="alert alert-danger" role="alert">{q.error.message}</div>}
      <Table columns={cols} rows={q.data ?? []} rowKey={(p) => p.key} loading={q.isLoading} caption="프로젝트 선택"
        empty={<Empty title="볼 수 있는 프로젝트가 없습니다" description="프로젝트를 만들거나 멤버로 초대받으면 여기에 나타납니다." />} />
    </>
  );
}
