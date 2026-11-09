import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import Table from "../../components/Table";
import { useApi } from "../../api/hooks";
import { ApiError, api, qs } from "../../api/client";
import { fmtDateTime } from "../../lib/format";
import type { AuditEntry, AuditPage, Project } from "../../api/types";
import { Loading } from "./parts";

const LIMIT = 50;

export default function Audit() {
  const projects = useApi<Project[]>("/projects");
  const [project, setProject] = useState("");
  const [action, setAction] = useState("");
  const [applied, setApplied] = useState({ project: "", action: "" });
  const q = useInfiniteQuery<AuditPage, ApiError, { pages: AuditPage[] }, unknown[], string>({
    queryKey: ["/audit", applied], initialPageParam: "",
    queryFn: ({ pageParam, signal }) => api.get<AuditPage>(`/audit${qs({ ...applied, limit: LIMIT, cursor: pageParam })}`, { signal }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows: AuditEntry[] = q.data?.pages.flatMap((p) => p.items ?? []) ?? [];
  const who = (e: AuditEntry) => e.actor || (e.actor_user ? `사용자 #${e.actor_user}` : e.actor_token ? `API 토큰 #${e.actor_token}` : "시스템");
  return (
    <>
      <PageHeader title="감사 로그" description="누가 언제 무엇을 바꿨는지 기록입니다. 최신순이며, 지울 수 없습니다." />
      <form className="panel" style={{ padding: 12, display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}
        onSubmit={(e) => { e.preventDefault(); setApplied({ project, action: action.trim() }); }}>
        <label className="field"><span className="field-label">프로젝트</span>
          <select className="input" value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">전체</option>{(projects.data ?? []).map((p) => <option key={p.id} value={p.key}>{p.name} ({p.key})</option>)}
          </select></label>
        <label className="field"><span className="field-label">동작</span>
          <input className="input" placeholder="예: sync.run" value={action} onChange={(e) => setAction(e.target.value)} /></label>
        <Button type="submit" variant="primary" icon="search">조회</Button>
      </form>
      <Loading q={q} />
      <div className="panel">
        <Table<AuditEntry> dense rowKey={(e) => e.id} rows={rows} loading={q.isLoading} caption="감사 로그" empty={<span className="muted">조건에 맞는 기록이 없습니다.</span>}
          columns={[
            { key: "at", header: "시각", nowrap: true, render: (e) => fmtDateTime(e.at) },
            { key: "who", header: "행위자", nowrap: true, render: who },
            { key: "action", header: "동작", mono: true, render: (e) => e.action },
            { key: "target", header: "대상", render: (e) => e.target || "-" },
            { key: "ip", header: "IP", mono: true, render: (e) => e.ip || "-" },
            { key: "d", header: "상세", render: (e) => { const s = JSON.stringify(e.details ?? {}); return s === "{}" ? "-" : <span className="mono muted" title={s}>{s.length > 80 ? `${s.slice(0, 80)}…` : s}</span>; } },
          ]} />
        {q.hasNextPage && <div style={{ padding: 12, textAlign: "center" }}><Button loading={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>더 보기</Button></div>}
      </div>
    </>
  );
}
