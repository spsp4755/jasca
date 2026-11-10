import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import Table from "../../components/Table";
import StatusBadge from "../../components/StatusBadge";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { fmtDateTime } from "../../lib/format";
import type { RecheckRun } from "../../api/types";
import { Panel, useSave } from "./parts";

const REASON = { trivydb: "Trivy DB 갱신", manual: "수동" };

/** Run list with progress; polls while a run is going. Shared with the Trivy page. */
export function RecheckRuns() {
  const q = useApi<RecheckRun[]>("/admin/recheck", { refetchInterval: (query) => (query.state.data?.some((r) => r.state === "running") ? 3000 : false) });
  const start = useSave(() => api.post("/admin/recheck"), { ok: "재평가를 시작했습니다.", invalidate: ["/admin/recheck"] });
  return (
    <Panel title="재평가 실행 기록" meta={<Button size="sm" icon="scan" loading={start.isPending} onClick={() => start.mutate(undefined)}>지금 재평가</Button>}>
      <p className="muted">저장된 스캔 결과를 최신 Trivy DB로 다시 대조합니다. 취약점 DB를 올리면 자동으로 실행됩니다. 새로 알려진 취약점은 알림 대상이 됩니다.</p>
      <Table<RecheckRun> dense rowKey={(r) => r.id} rows={q.data ?? []} loading={q.isLoading} caption="재평가 실행 기록" empty={<span className="muted">{q.error ? `기록을 불러오지 못했습니다. ${q.error.message}` : "아직 실행 기록이 없습니다."}</span>}
        columns={[
          { key: "at", header: "시작", nowrap: true, render: (r) => fmtDateTime(r.started_at) },
          { key: "reason", header: "사유", nowrap: true, render: (r) => REASON[r.reason] ?? r.reason },
          { key: "state", header: "상태", render: (r) => <><StatusBadge status={r.state === "done" ? "done" : r.state === "canceled" ? "canceled" : r.state} />{r.error && <div className="muted">{r.error}</div>}</> },
          { key: "prog", header: "진행", render: (r) => {
            const pct = r.total ? Math.round((r.done / r.total) * 100) : r.state === "done" ? 100 : 0;
            return <div style={{ display: "flex", gap: 8, alignItems: "center" }}><div className="progress" role="progressbar" aria-label={`재평가 #${r.id} 진행률`} aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${pct}%` }} /></div><span className="num nw">{r.done}/{r.total}</span></div>;
          } },
          { key: "new", header: "새 취약점", align: "right", render: (r) => <span className="num">{r.new_findings}</span> },
          { key: "end", header: "종료", nowrap: true, render: (r) => (r.finished_at ? fmtDateTime(r.finished_at) : "-") },
        ]} />
    </Panel>
  );
}

export default function Recheck() {
  return <><PageHeader title="재평가" /><RecheckRuns /></>;
}
