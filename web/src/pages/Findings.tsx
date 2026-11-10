import { useInfiniteQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type Key } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { API_BASE, ApiError, api, qs } from "../api/client";
import { isSecurity, useApi, useMe } from "../api/hooks";
import type { Finding, FindingPage, Project, Target } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import FilterBar, { readFilters } from "../components/FilterBar";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import Table, { type Column } from "../components/Table";
import { KIND_LABEL, fmtDate, fmtDaysAgo, fmtNumber } from "../lib/format";
import FindingDrawer, { ExceptionRequestDialog, canAskFor } from "./FindingDrawer";
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
  const [sp, setSp] = useSearchParams();
  const filters = { ...readFilters(sp), ...(project ? { project } : {}) };
  const query = qs(filters);
  const q = useInfiniteQuery<FindingPage, ApiError, { pages: FindingPage[] }, unknown[], string | undefined>({
    queryKey: [`/findings${query}`], initialPageParam: undefined,
    queryFn: ({ pageParam, signal }) => api.get<FindingPage>(`/findings${qs({ ...filters, limit: LIMIT, cursor: pageParam })}`, { signal }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows = useMemo(() => q.data?.pages.flatMap((p) => p.items ?? []) ?? [], [q.data]);
  const total = q.data?.pages[0]?.total;
  const [selected, setSelected] = useState<Set<Key>>(new Set());
  // the open drawer lives in the URL (?finding=<id>) so a link opens it; the list filters ignore that key
  const openId = Number(sp.get("finding")) || null;
  const fetched = useApi<Finding>(openId && !rows.some((r) => r.id === openId) ? `/findings/${openId}` : null);
  const open = (openId && (rows.find((r) => r.id === openId) ?? fetched.data)) || null;
  const setOpen = (f: Finding | null) => setSp((p) => {
    const n = new URLSearchParams(p);
    if (f) n.set("finding", String(f.id)); else n.delete("finding");
    return n;
  }, { replace: true });
  const [ask, setAsk] = useState(false);
  useEffect(() => setSelected(new Set()), [query]);
  // rows are chosen only to ask for an exception, so the checkboxes follow who may ask (the drawer's rule)
  const sec = isSecurity(useMe().data);
  const roles = useApi<Project[]>("/projects").data;
  const canAsk = (r: Finding) => canAskFor(r, roles?.find((p) => p.key === r.project_key)?.my_role, sec);
  const anyAsk = sec || !!roles?.some((p) => (project ? p.key === project : true) && (p.my_role === "member" || p.my_role === "owner"));
  const picked = rows.filter((r) => selected.has(r.id) && r.status === "open"); // only open findings can get an exception

  const columns: Column<Finding>[] = [
    { key: "sev", header: "심각도", width: 108, render: (r) => <SeverityBadge severity={r.severity} /> },
    {
      key: "rule", header: "취약점", width: "34%", render: (r) => (
        <span className="rule">
          {r.kind === "vuln" ? <Link to={`/vulns/${encodeURIComponent(r.rule_id)}`} className="mono nw">{r.rule_id}</Link> : <span className="mono">{r.rule_id}</span>}
          {r.kind !== "vuln" && <span className="tag tag-quiet">{KIND_LABEL[r.kind]}</span>}
          {r.title && <span className="rule-title" title={r.title}>{r.title}</span>}
        </span>
      ),
    },
    { key: "pkg", header: "패키지 · 조치 버전", width: "22%", render: (r) => (r.pkg_name ? <PkgCell name={r.pkg_name} version={r.pkg_version} fixed={r.fixed_version} /> : <span className="mono muted break">{r.location || "—"}</span>) },
    project
      ? { key: "target", header: "대상", width: "18%", nowrap: true, render: (r) => <span className="pt-target mono" title={r.target_name}>{r.target_name}</span> }
      : { key: "where", header: "프로젝트 · 대상", width: "18%", nowrap: true, render: (r) => <ProjectTarget project={r.project_key} target={r.target_name} /> }, // nowrap + width: cut with an ellipsis, so this column gives way first
    { key: "status", header: "상태", width: 96, render: (r) => <StatusBadge status={r.status} /> },
    { key: "seen", header: "처음 발견", width: 92, align: "right", render: (r) => <span className="num muted" title={fmtDate(r.first_seen_at)}>{fmtDaysAgo(r.first_seen_at)}</span> },
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
            <span className="num">{selected.size}건 선택{picked.length < selected.size && ` (열린 결과 ${picked.length}건)`}</span>
            <Button size="sm" variant="primary" icon="shield" disabled={picked.length === 0} onClick={() => setAsk(true)}>예외 요청</Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>선택 해제</Button>
          </span>
        )}
        <a className="btn btn-secondary btn-sm result-csv" href={`${API_BASE}/findings.csv${query}`} download>
          <Icon name="table" size={14} />CSV 내려받기
        </a>
      </div>
      {openId && fetched.isError && (
        <div className="alert alert-warn" role="alert"><Icon name="alert" />
          {fetched.error.status === 404 ? `이 결과(#${openId})를 찾을 수 없습니다. 삭제되었거나 볼 권한이 없는 프로젝트의 결과입니다.` : fetched.error.message}
          <Button size="sm" className="alert-action" onClick={() => setOpen(null)}>닫기</Button></div>
      )}
      {q.isError && (
        <div className="alert alert-danger" role="alert"><Icon name="alert" />{q.error.message}
          <Button size="sm" className="alert-action" onClick={() => q.refetch()}>다시 시도</Button></div>
      )}
      <div className="panel">
        <Table caption="결과 목록" rows={rows} rowKey={(r) => r.id} columns={columns} loading={q.isPending} dense
          {...(anyAsk ? { selected, onSelectedChange: setSelected, selectableRow: canAsk } : {})} onRowClick={setOpen}
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
