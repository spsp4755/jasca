import { useInfiniteQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type Key } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { API_BASE, ApiError, api, qs } from "../api/client";
import { useApi } from "../api/hooks";
import type { Finding, FindingPage, Project, Target } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import FilterBar, { readFilters } from "../components/FilterBar";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import Table, { type Column } from "../components/Table";
import { KIND_LABEL, daysSince, fmtDate, fmtNumber } from "../lib/format";
import FindingDrawer, { ExceptionRequestDialog } from "./FindingDrawer";
import { PkgCell, ProjectTarget } from "./Home";

const LIMIT = 100;

export default function Findings() {
  const projects = useApi<Project[]>("/projects");
  return (
    <>
      <PageHeader title="취약점" description="볼 수 있는 모든 프로젝트의 결과입니다. 필터는 주소에 남아 그대로 공유할 수 있습니다." />
      <FindingsView projects={projects.data ?? []} />
    </>
  );
}

/** Filter bar + findings table + drawer + bulk exception request. With `project`, scoped to that project. */
export function FindingsView({ project, projects, targets }: { project?: string; projects?: Project[]; targets?: Target[] }) {
  const [sp] = useSearchParams();
  const filters = { ...readFilters(sp), ...(project ? { project } : {}) };
  const query = qs(filters);
  const q = useInfiniteQuery<FindingPage, ApiError, { pages: FindingPage[] }, unknown[], number | undefined>({
    queryKey: [`/findings${query}`], initialPageParam: undefined,
    queryFn: ({ pageParam, signal }) => api.get<FindingPage>(`/findings${qs({ ...filters, limit: LIMIT, cursor: pageParam })}`, { signal }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows = useMemo(() => q.data?.pages.flatMap((p) => p.items ?? []) ?? [], [q.data]);
  const total = q.data?.pages[0]?.total;
  const [selected, setSelected] = useState<Set<Key>>(new Set());
  const [open, setOpen] = useState<Finding | null>(null);
  const [ask, setAsk] = useState(false);
  useEffect(() => setSelected(new Set()), [query]);
  const picked = rows.filter((r) => selected.has(r.id));

  const columns: Column<Finding>[] = [
    { key: "sev", header: "심각도", width: 92, render: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: "rule", header: "취약점", render: (r) => (
        <span className="rule">
          {r.kind === "vuln" ? <Link to={`/vulns/${encodeURIComponent(r.rule_id)}`} className="mono">{r.rule_id}</Link> : <span className="mono">{r.rule_id}</span>}
          {r.kind !== "vuln" && <span className="tag tag-quiet">{KIND_LABEL[r.kind]}</span>}
          {r.title && <span className="rule-title" title={r.title}>{r.title}</span>}
        </span>
      ),
    },
    { key: "pkg", header: "패키지 · 조치 버전", width: "24%", render: (r) => (r.pkg_name ? <PkgCell name={r.pkg_name} version={r.pkg_version} fixed={r.fixed_version} /> : <span className="mono muted break">{r.location || "—"}</span>) },
    project
      ? { key: "target", header: "대상", width: "20%", render: (r) => <span className="pt-target mono" title={r.target_name}>{r.target_name}</span> }
      : { key: "where", header: "프로젝트 · 대상", width: "20%", render: (r) => <ProjectTarget project={r.project_key} target={r.target_name} /> },
    { key: "status", header: "상태", width: 96, render: (r) => <StatusBadge status={r.status} /> },
    { key: "seen", header: "처음 발견", width: 92, align: "right", render: (r) => <span className="num muted" title={fmtDate(r.first_seen_at)}>{daysSince(r.first_seen_at)}일 전</span> },
  ];

  return (
    <div className="findings">
      <FilterBar projects={project ? undefined : projects} targets={targets} />
      <div className="result-bar">
        <span className="result-count" aria-live="polite">
          {total === undefined ? (q.isError ? "" : "불러오는 중…") : <><b className="num">{fmtNumber(total)}</b>건</>}
          {rows.length > 0 && total !== undefined && rows.length < total && <span className="muted"> · {fmtNumber(rows.length)}건 표시</span>}
        </span>
        {selected.size > 0 && (
          <span className="bulk">
            <span className="num">{selected.size}건 선택</span>
            <Button size="sm" variant="primary" icon="shield" onClick={() => setAsk(true)}>예외 요청</Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>선택 해제</Button>
          </span>
        )}
        <a className="btn btn-secondary btn-sm result-csv" href={`${API_BASE}/findings.csv${query}`} download>
          <Icon name="table" size={14} />CSV 내려받기
        </a>
      </div>
      {q.isError && (
        <div className="alert alert-danger" role="alert"><Icon name="alert" />{q.error.message}
          <Button size="sm" className="alert-action" onClick={() => q.refetch()}>다시 시도</Button></div>
      )}
      <div className="panel">
        <Table caption="결과 목록" rows={rows} rowKey={(r) => r.id} columns={columns} loading={q.isPending} dense
          selected={selected} onSelectedChange={setSelected} onRowClick={setOpen}
          empty={(
            <Empty compact icon="shieldCheck" title="조건에 맞는 결과가 없습니다"
              description={filters.status === "open" ? "열린 결과만 보고 있습니다. 해결되거나 예외 처리된 결과도 보려면 상태를 '모든 상태'로 바꾸세요." : "필터를 줄이거나 검색어를 바꿔 보세요."} />
          )} />
        {q.hasNextPage && (
          <div className="more"><Button loading={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>{LIMIT}건 더 보기</Button></div>
        )}
      </div>
      <FindingDrawer finding={open} onClose={() => setOpen(null)} showProject={!project} />
      <ExceptionRequestDialog open={ask} findings={picked} onClose={() => setAsk(false)} onDone={() => setSelected(new Set())} />
    </div>
  );
}
