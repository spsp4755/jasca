import { useInfiniteQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, qs, type ApiError } from "../api/client";
import { useApi } from "../api/hooks";
import type { Project, Scan, ScanPage, Target } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import StatusBadge from "../components/StatusBadge";
import Table from "../components/Table";
import { SOURCE_LABEL, TARGET_KIND_LABEL, fmtDateTime, fmtRelative } from "../lib/format";
import { PolicyCell, SummaryCell } from "./Home";
import { FirstScan } from "./ProjectFindings";

const LIMIT = 50;

export default function ProjectScans({ project }: { project: Project }) {
  const navigate = useNavigate();
  const [sp, setSp] = useSearchParams();
  const targetId = sp.get("target_id") ?? "";
  const targets = useApi<Target[] | null>(`/projects/${project.key}/targets`);
  const base = `/projects/${project.key}/scans`;
  const q = useInfiniteQuery<ScanPage, ApiError, { pages: ScanPage[] }, unknown[], number | undefined>({
    queryKey: [base, targetId], initialPageParam: undefined,
    queryFn: ({ pageParam, signal }) => api.get<ScanPage>(`${base}${qs({ target_id: targetId, limit: LIMIT, before: pageParam })}`, { signal }),
    getNextPageParam: (last) => last.next_before ?? undefined,
    // keep queued/running rows moving without a manual refresh
    refetchInterval: (query) => (query.state.data?.pages[0]?.items?.some((s) => s.status === "queued" || s.status === "running") ? 5000 : false),
  });
  const rows = q.data?.pages.flatMap((p) => p.items ?? []) ?? [];
  if (q.isSuccess && !rows.length && !targetId) return <FirstScan project={project} />;
  const list = targets.data ?? [];
  return (
    <>
      {list.length > 1 && (
        <div className="filterbar">
          <select className="input" aria-label="대상" value={targetId} onChange={(e) => setSp(e.target.value ? { target_id: e.target.value } : {}, { replace: true })}>
            <option value="">모든 대상</option>
            {list.map((t) => <option key={t.id} value={t.id}>{TARGET_KIND_LABEL[t.kind]} · {t.name}</option>)}
          </select>
        </div>
      )}
      {q.isError && <div className="alert alert-danger" role="alert"><Icon name="alert" />{q.error.message}</div>}
      <div className="panel">
        <Table<Scan> caption="스캔 기록" rows={rows} rowKey={(s) => s.id} loading={q.isPending} dense onRowClick={(s) => navigate(`/scans/${s.id}`)}
          empty={<Empty compact icon="scan" title="이 대상의 스캔이 없습니다" />}
          columns={[
            { key: "at", header: "시각", width: 120, render: (s) => <span title={fmtDateTime(s.created_at)}>{fmtRelative(s.created_at)}</span> },
            { key: "target", header: "대상", render: (s) => (
              <span className="pt">
                <span className="pt-project mono">{s.target_name}</span>
                <span className="pt-target">{TARGET_KIND_LABEL[s.target_kind] ?? s.target_kind}{s.ref && <> · <span className="mono">{s.ref}</span></>}</span>
              </span>) },
            { key: "source", header: "방식", width: 100, render: (s) => <span className="muted nw">{SOURCE_LABEL[s.source] ?? s.source}</span> },
            { key: "status", header: "상태", width: 96, render: (s) => <StatusBadge status={s.status} /> },
            { key: "summary", header: "열린 결과", width: 260, render: (s) => (s.status === "done" ? <SummaryCell s={s.summary} /> : <span className="muted clamp" title={s.error}>{s.error || "—"}</span>) },
            { key: "policy", header: "정책", width: 84, render: (s) => <PolicyCell s={s} /> },
          ]} />
        {q.hasNextPage && <div className="more"><Button loading={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>이전 스캔 더 보기</Button></div>}
      </div>
    </>
  );
}
