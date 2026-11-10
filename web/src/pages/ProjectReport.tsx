import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import Table from "../components/Table";
import Button from "../components/Button";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import Empty from "../components/Empty";
import { PkgCell, SummaryCell } from "./Home";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../api/client";
import { useApi, useAuthConfig } from "../api/hooks";
import { RESOLUTION_LABEL, SCOPE_LABEL, SEVERITY_LABEL, TARGET_KIND_LABEL, fmtDate, fmtDateTime, fmtNumber } from "../lib/format";
import { exceptionWhat } from "./Exceptions";
import { renderMarkdown } from "../lib/markdown";
import type { AiRun, ProjectReportData, RunRef } from "../api/types";
import { Loading } from "./admin/parts";
import "../styles/t17.css";
import "../styles/print.css";

const RUNNING = ["queued", "running"];
const RUN_LABEL: Record<AiRun["state"], string> = { queued: "대기 중", running: "작성 중", done: "완료", failed: "실패" };

export default function ProjectReport() {
  const { key = "" } = useParams();
  const k = encodeURIComponent(key);
  const toast = useToast();
  const qc = useQueryClient();
  const q = useApi<ProjectReportData>(`/projects/${k}/report`);
  const ai = useAuthConfig().data?.ai_enabled;
  const runs = useApi<AiRun[]>(ai && !q.isError ? `/projects/${k}/ai-reports` : null, {
    refetchInterval: (query) => (query.state.data?.some((r) => RUNNING.includes(r.state)) ? 3000 : false), staleTime: 0,
  });
  const [sel, setSel] = useState<number | null>(null);
  const gen = useMutation<RunRef, ApiError>({
    mutationFn: () => api.post<RunRef>(`/projects/${k}/ai-report`),
    onSuccess: (r) => { toast("AI 보고서 작성을 시작했습니다.", "ok"); setSel(r.run_id); void qc.invalidateQueries({ queryKey: [`/projects/${k}/ai-reports`] }); },
    onError: (e) => toast(e.message, "error"),
  });
  const d = q.data;
  const history = runs.data ?? [];
  const shown = history.find((r) => r.id === sel) ?? history.find((r) => r.state === "done");
  const t = d?.summary.by_severity;
  const pol = d?.policy;
  // the API sends the 100 most severe open findings; the report lists the CRITICAL and HIGH ones and counts the rest
  const top = (d?.findings ?? []).filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
  const rest = t ? (["medium", "low", "unknown"] as const).filter((s) => t[s] > 0).map((s) => `${s.toUpperCase()} ${fmtNumber(t[s])}건`) : [];
  if (q.isError) { // nothing to print or summarise: only say so
    const missing = q.error.status === 404;
    return (
      <>
        <PageHeader title="프로젝트 보고서" crumbs={[{ label: "보고서", to: "/reports" }, { label: key }]} />
        <div className="panel">
          <Empty icon={missing ? "folder" : "alert"} title={missing ? "프로젝트를 찾을 수 없습니다" : "보고서를 불러오지 못했습니다"}
            description={missing ? "키가 틀렸거나, 삭제되었거나, 멤버가 아닌 프로젝트입니다. 소유자에게 멤버 추가를 요청하세요." : q.error.message}
            action={<Link to="/reports" className="btn btn-secondary btn-sm">보고서 목록</Link>} />
        </div>
      </>
    );
  }
  return (
    <>
      <PageHeader title={d?.project?.name ? `${d.project.name} 보고서` : "프로젝트 보고서"} crumbs={[{ label: "보고서", to: "/reports" }, { label: key }]}
        actions={<span className="no-print row-gap"><Button icon="fileText" onClick={() => window.print()}>인쇄 / PDF</Button>
          {ai && <Button variant="primary" loading={gen.isPending} disabled={history.some((r) => RUNNING.includes(r.state))} onClick={() => gen.mutate()}>AI 보고서 만들기</Button>}</span>} />
      <Loading q={q} />
      <div className={`report-split${ai ? "" : " report-solo"}`}>
        <article className="report-doc" aria-label="프로젝트 현황 보고서">
          {d && (
            <>
              <header>
                <h2 style={{ fontSize: 20 }}>{d.project?.name ?? key} <span className="muted mono" style={{ fontSize: 13 }}>{key}</span></h2>
                {d.project?.description && <p className="muted" style={{ margin: 0 }}>{d.project.description}</p>}
                <p className="muted" style={{ margin: "4px 0 0" }}>작성 {fmtDateTime(d.generated_at ?? new Date().toISOString())}</p>
              </header>
              {t && <section><h2>요약</h2><div className="sev-row">
                {(["critical", "high", "medium", "low", "unknown"] as const).map((s) => <SeverityBadge key={s} severity={s.toUpperCase() as "LOW"} count={t[s] ?? 0} />)}
                <span className="muted num">열린 결과 {fmtNumber(t.open ?? 0)}</span></div></section>}
              {pol && <section><h2>정책</h2><p>{pol.enabled
                ? `열린 결과 중 심각도 ${SEVERITY_LABEL[pol.min_severity] ?? pol.min_severity} 이상이 ${pol.max_count}개를 넘으면 정책 실패입니다.${pol.new_only ? " 이번 스캔에서 새로 나온 결과만 셉니다." : ""}${pol.fixable_only ? " 조치 버전이 있는 결과만 셉니다." : ""}`
                : "정책을 쓰지 않습니다. 스캔은 항상 정책 통과로 표시됩니다."}</p></section>}
              {(d.targets ?? []).length > 0 && <section><h2>대상별 현황</h2>
                <Table dense rows={d.targets} rowKey={(r) => r.name} caption="대상별 현황" columns={[
                  { key: "n", header: "대상", render: (r) => r.name }, { key: "k", header: "종류", render: (r) => TARGET_KIND_LABEL[r.kind] ?? r.kind },
                  { key: "c", header: "열린 결과 심각도별", render: (r) => <SummaryCell s={r.counts} /> },
                  { key: "s", header: "마지막 스캔", nowrap: true, render: (r) => fmtDate(r.last_scan_at) }]} /></section>}
              {(d.findings ?? []).length > 0 && <section className="page-break"><h2>주요 취약점</h2>
                <p className="muted" style={{ margin: "0 0 8px" }}>{top.length === 0 ? "열린 CRITICAL·HIGH 결과가 없습니다." : `CRITICAL·HIGH만 싣습니다${t && t.critical + t.high > top.length ? `(많아서 앞의 ${fmtNumber(top.length)}건)` : ""}.`}
                  {rest.length > 0 && ` ${rest.join(", ")}은 프로젝트의 결과 화면에서 볼 수 있습니다.`}</p>
                {top.length > 0 && <Table dense rows={top} rowKey={(r) => r.id} caption="주요 취약점" columns={[
                  { key: "s", header: "심각도", width: 100, render: (r) => <SeverityBadge severity={r.severity} /> },
                  { key: "i", header: "취약점", render: (r) => <span className="rule"><span className={r.kind === "vuln" ? "mono nw" : "mono"}>{r.rule_id}</span>{r.title && <span className="rule-title" title={r.title}>{r.title}</span>}</span> },
                  { key: "p", header: "패키지 · 조치 버전", width: "30%", render: (r) => (r.pkg_name ? <PkgCell name={r.pkg_name} version={r.pkg_version} fixed={r.fixed_version} /> : <span className="muted">—</span>) },
                  { key: "t", header: "대상", nowrap: true, render: (r) => r.target }]} />}</section>}
              {(d.exceptions ?? []).length > 0 && <section><h2>예외</h2>
                <Table dense rows={d.exceptions} rowKey={(r) => r.id} caption="예외" columns={[
                  { key: "v", header: "취약점", mono: true, render: exceptionWhat }, { key: "sc", header: "범위", render: (r) => SCOPE_LABEL[r.scope] },
                  { key: "r", header: "처리", render: (r) => RESOLUTION_LABEL[r.resolution] }, { key: "st", header: "상태", render: (r) => <StatusBadge status={r.status} /> },
                  { key: "e", header: "만료", render: (r) => fmtDate(r.expires_at) }]} /></section>}
              {shown?.state === "done" && <section className="page-break"><h2>AI 요약 ({fmtDateTime(shown.finished_at ?? shown.created_at)})</h2><div className="md">{renderMarkdown(shown.output)}</div></section>}
            </>
          )}
        </article>
        {ai === false && <p className="side-note no-print">AI 안내는 관리자가 켜면 쓸 수 있습니다.</p>}
        {ai && <aside className="panel no-print">
          <div className="panel-head"><h2>AI 보고서 기록</h2></div>
          <div className="panel-body stack">
            <p className="muted" style={{ margin: 0 }}>AI가 쓴 내용은 틀릴 수 있습니다. 공유 전에 검토하세요.</p>
            {runs.error && <div className="alert alert-danger">{runs.error.message}</div>}
            {history.length === 0 && !runs.isLoading && <p className="muted">아직 만든 보고서가 없습니다. &quot;AI 보고서 만들기&quot;를 눌러 보세요.</p>}
            <ul className="list" style={{ listStyle: "none", margin: 0, padding: 0 }}>
              {history.map((r) => (
                <li key={r.id} className="list-row"><button type="button" className="btn btn-ghost btn-sm" aria-pressed={shown?.id === r.id} onClick={() => setSel(r.id)}>
                  {fmtDateTime(r.created_at)}</button><span className="muted">{RUN_LABEL[r.state]}</span></li>
              ))}
            </ul>
            {shown?.state === "failed" && <div className="alert alert-danger" role="alert">{shown.error || "AI 보고서를 만들지 못했습니다."}</div>}
            {shown && RUNNING.includes(shown.state) && <p role="status">작성 중입니다. 잠시 후 자동으로 나타납니다.</p>}
          </div>
        </aside>}
      </div>
    </>
  );
}
