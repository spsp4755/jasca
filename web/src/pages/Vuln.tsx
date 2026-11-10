import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type ApiError } from "../api/client";
import { useApi, useAuthConfig } from "../api/hooks";
import type { AiRun, RunRef, Severity, Vuln as VulnT, VulnAffected } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import Table from "../components/Table";
import { fmtDate, fmtDateTime, fmtNumber } from "../lib/format";
import { renderMarkdown } from "../lib/markdown";
import { PkgCell } from "./Home";

const SAFE_URL = /^https?:\/\//i;
const band = (score: number): Severity => (score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : score > 0 ? "LOW" : "UNKNOWN");
const host = (u: string) => { try { return new URL(u).host; } catch { return u; } };

export default function Vuln() {
  const { id = "" } = useParams();
  const q = useApi<VulnT>(`/vulns/${encodeURIComponent(id)}`);
  const ai = useAuthConfig().data?.ai_enabled;
  const crumbs = [{ label: "취약점", to: "/findings" }, { label: id }];
  if (q.isError) {
    return (
      <>
        <PageHeader title={id} crumbs={crumbs} />
        <div className="panel">
          {q.error.status === 404
            ? <Empty icon="search" title="카탈로그에 없는 취약점입니다" description="이 ID가 들어 있는 스캔 결과가 아직 올라온 적이 없습니다. ID를 확인하거나 결과 검색에서 찾아보세요."
                action={<Link className="btn btn-secondary btn-sm" to={`/findings?q=${encodeURIComponent(id)}&status=`}>결과에서 찾기</Link>} />
            : <Empty icon="alert" title="취약점 정보를 불러오지 못했습니다" description={q.error.message} action={<Button size="sm" onClick={() => q.refetch()}>다시 시도</Button>} />}
        </div>
      </>
    );
  }
  const v = q.data;
  const affected = v?.affected ?? [];
  const open = affected.filter((a) => a.status === "open");
  return (
    <>
      <PageHeader crumbs={crumbs} title={id}
        description={v ? v.title || "제목 없음" : <span className="skeleton" style={{ width: 280 }} />}
        actions={<Link className="btn btn-secondary" to={`/findings?q=${encodeURIComponent(id)}&status=`}><Icon name="search" />결과에서 보기</Link>} />
      <div className="detail-grid">
        <div className="detail-main">
          <section className="panel" aria-labelledby="h-desc">
            <div className="panel-head"><h2 id="h-desc">설명</h2></div>
            <div className="panel-body">
              {!v ? <span className="skeleton skeleton-block" style={{ height: 80 }} />
                : v.description ? <p className="prose pre">{v.description}</p> : <p className="muted">스캐너 보고서에 설명이 없습니다.</p>}
            </div>
          </section>

          <section className="panel" aria-labelledby="h-aff">
            <div className="panel-head">
              <h2 id="h-aff">영향받는 대상</h2>
              {v && <span className="panel-meta">열림 {fmtNumber(open.length)} · 전체 {fmtNumber(affected.length)} · 볼 수 있는 프로젝트만</span>}
            </div>
            <Table<VulnAffected> caption="영향받는 대상" rows={affected} rowKey={(a) => a.finding_id} loading={q.isPending} dense maxHeight={480}
              empty={<Empty compact icon="shieldCheck" title="내가 볼 수 있는 프로젝트에는 이 취약점이 없습니다" />}
              columns={[
                { key: "where", header: "프로젝트 · 대상", render: (a) => (
                  <span className="pt">
                    <Link to={`/projects/${encodeURIComponent(a.project_key)}?q=${encodeURIComponent(id)}&status=`} className="pt-project">{a.project_key}</Link>
                    <span className="pt-target mono" title={a.target}>{a.target}</span>
                  </span>) },
                { key: "pkg", header: "패키지 · 조치 버전", render: (a) => <PkgCell name={a.pkg_name} version={a.pkg_version} fixed={a.fixed_version} /> },
                { key: "sev", header: "심각도", width: 108, render: (a) => <SeverityBadge severity={a.severity} /> },
                { key: "status", header: "상태", width: 96, render: (a) => <StatusBadge status={a.status} /> },
              ]} />
          </section>

          {v && (ai ? <AiGuide v={v} /> : ai === false && <p className="side-note">AI 안내는 관리자가 켜면 쓸 수 있습니다.</p>)}
        </div>

        <aside className="detail-side">
          <section className="panel" aria-labelledby="h-meta">
            <div className="panel-head"><h2 id="h-meta">개요</h2></div>
            <div className="panel-body">
              {!v ? <span className="skeleton skeleton-block" style={{ height: 120 }} /> : (
                <>
                  <div className="cvss">
                    {v.cvss_score != null ? (
                      <>
                        <span className={`cvss-score cvss-${band(v.cvss_score).toLowerCase()}`}>{v.cvss_score.toFixed(1)}</span>
                        <span className="cvss-text"><b>CVSS</b><SeverityBadge severity={band(v.cvss_score)} /></span>
                      </>
                    ) : <span className="muted">CVSS 점수 없음</span>}
                  </div>
                  {v.cvss_vector && <p className="mono cvss-vector break" title="CVSS 벡터">{v.cvss_vector}</p>}
                  <p className="side-note">심각도는 결과마다 다를 수 있습니다. 배포판(Debian 등)이 매긴 값이 결과에 그대로 남습니다.</p>
                  <dl className="kv kv-tight">
                    <div className="kv-row"><dt>공개일</dt><dd>{fmtDate(v.published_at)}</dd></div>
                    <div className="kv-row"><dt>최종 수정</dt><dd>{fmtDate(v.last_modified_at)}</dd></div>
                    {(v.cwe_ids ?? []).length > 0 && <div className="kv-row"><dt>CWE</dt><dd className="tags">{v.cwe_ids.map((c) => <span key={c} className="tag tag-quiet">{c}</span>)}</dd></div>}
                  </dl>
                </>
              )}
            </div>
          </section>
          {v && (v.refs ?? []).length > 0 && (
            <section className="panel" aria-labelledby="h-refs">
              <div className="panel-head"><h2 id="h-refs">참고 자료</h2><span className="panel-meta">{v.refs.length}개</span></div>
              <ul className="refs">
                {v.refs.map((r) => (
                  <li key={r}>{SAFE_URL.test(r)
                    ? <a href={r} target="_blank" rel="noopener noreferrer" title={r}><span className="ref-host">{host(r)}</span><span className="ref-path">{r.replace(/^https?:\/\/[^/]+/i, "") || "/"}</span></a>
                    : <span className="mono muted break">{r}</span>}</li>
                ))}
              </ul>
            </section>
          )}
        </aside>
      </div>
    </>
  );
}

/** POST /vulns/{id}/ai-guide starts a run; poll GET /ai/runs/{id} until done or failed and render its Markdown. */
function AiGuide({ v }: { v: VulnT }) {
  const qc = useQueryClient();
  const [runId, setRunId] = useState<number | null>(null);
  useEffect(() => setRunId(null), [v.id]);
  const start = useMutation<RunRef, ApiError>({
    mutationFn: () => api.post<RunRef>(`/vulns/${encodeURIComponent(v.id)}/ai-guide`),
    onSuccess: (r) => setRunId(r.run_id),
  });
  const run = useApi<AiRun>(runId ? `/ai/runs/${runId}` : null, {
    staleTime: 0,
    refetchInterval: (query) => (["done", "failed"].includes(query.state.data?.state ?? "") || query.state.error ? false : 2000),
  });
  const state = run.data?.state;
  useEffect(() => { if (state === "done") qc.invalidateQueries({ queryKey: [`/vulns/${encodeURIComponent(v.id)}`] }); }, [state, qc, v.id]);
  const working = start.isPending || (!!runId && (!state || state === "queued" || state === "running") && !run.isError);
  const err = start.error?.message || run.error?.message || (state === "failed" ? run.data?.error || "안내를 만들지 못했습니다." : "");

  return (
    <section className="panel ai" aria-labelledby="h-ai" aria-busy={working || undefined}>
      <div className="panel-head">
        <h2 id="h-ai"><Icon name="info" size={15} />AI 조치 안내</h2>
        {state === "done" && run.data?.finished_at && <span className="panel-meta">{fmtDateTime(run.data.finished_at)} 작성</span>}
        {!runId && v.ai_guide_at && <span className="panel-meta">저장된 일반 설명 · {fmtDate(v.ai_guide_at)}</span>}
        <span className="panel-actions">
          <Button size="sm" variant={state === "done" || v.ai_guide ? "secondary" : "primary"} loading={working} onClick={() => start.mutate()}>
            {state === "done" ? "다시 만들기" : "내 프로젝트 기준 안내 받기"}
          </Button>
        </span>
      </div>
      <div className="panel-body">
        {err && <div className="alert alert-danger" role="alert"><Icon name="alert" />{err}</div>}
        {working ? (
          <div className="ai-working" role="status">
            <span className="spinner" aria-hidden="true" />
            <span>{state === "running" ? "AI가 안내를 쓰는 중입니다…" : "작업 대기 중입니다…"} 보통 1분 안에 끝나며, 이 화면을 떠나도 작업은 계속됩니다.</span>
          </div>
        ) : state === "done" && run.data ? (
          <div className="md">{renderMarkdown(run.data.output)}</div>
        ) : v.ai_guide ? (
          <>
            <div className="md">{renderMarkdown(v.ai_guide)}</div>
            <p className="side-note">위 내용은 이 취약점의 일반 설명입니다. 버튼을 누르면 내가 볼 수 있는 프로젝트의 패키지·버전을 반영한 조치 순서를 함께 만듭니다.</p>
          </>
        ) : !err && (
          <p className="muted">이 취약점의 요약과, 내 프로젝트에서 무엇을 어떤 순서로 올려야 하는지 한국어로 정리해 줍니다. 사내 AI 서버만 사용합니다.</p>
        )}
        {(state === "done" || (!working && v.ai_guide)) && <p className="ai-note"><Icon name="alert" size={13} />AI가 만든 안내입니다. 적용 전에 공식 권고와 버전을 확인하세요.</p>}
      </div>
    </section>
  );
}
