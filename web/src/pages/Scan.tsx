import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { API_BASE, api, qs, type ApiError } from "../api/client";
import { useApi } from "../api/hooks";
import { SEVERITIES, type Counts, type Finding, type FindingPage, type Project, type ScanDetail } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import Table from "../components/Table";
import Tabs from "../components/Tabs";
import { useToast } from "../components/Toast";
import { SEVERITY_LABEL, SOURCE_LABEL, TARGET_KIND_LABEL, fmtDateTime, fmtNumber } from "../lib/format";
import FindingDrawer from "./FindingDrawer";
import { PkgCell } from "./Home";

const MAX_ROWS = 5000;

/** Every finding linked to a scan, page by page (the API caps a page at 200). */
async function scanFindings(id: number, signal: AbortSignal) {
  const out: Finding[] = [];
  let cursor: number | undefined;
  do {
    const p = await api.get<FindingPage>(`/scans/${id}/findings${qs({ limit: 200, cursor })}`, { signal });
    out.push(...(p.items ?? []));
    cursor = p.next_cursor ?? undefined;
  } while (cursor && out.length < MAX_ROWS);
  return { items: out, truncated: !!cursor };
}

const live = (s?: string) => s === "queued" || s === "running";

export default function Scan() {
  const { id = "" } = useParams();
  const toast = useToast();
  const qc = useQueryClient();
  const q = useApi<ScanDetail>(`/scans/${id}`, { refetchInterval: (query) => (live(query.state.data?.status) ? 3000 : false) });
  const projects = useApi<Project[]>("/projects");
  const s = q.data;
  const project = projects.data?.find((p) => p.id === s?.project_id);
  const done = s?.status === "done";
  const prevId = s?.diff.previous_scan_id ?? null;
  const cur = useQuery({ queryKey: ["scan-findings", s?.id], enabled: done, queryFn: ({ signal }) => scanFindings(s!.id, signal) });
  const prev = useQuery({ queryKey: ["scan-findings", prevId], enabled: done && !!prevId, queryFn: ({ signal }) => scanFindings(prevId!, signal) });
  const [tab, setTab] = useState("new");
  const [open, setOpen] = useState<Finding | null>(null);
  const cancel = useMutation<unknown, ApiError>({
    mutationFn: () => api.post(`/scans/${id}/cancel`),
    onSuccess: () => { toast("스캔을 취소했습니다.", "ok"); qc.invalidateQueries({ queryKey: [`/scans/${id}`] }); },
    onError: (e) => toast(e.message, "error"),
  });

  if (q.isError) {
    return (
      <>
        <PageHeader title={`스캔 #${id}`} crumbs={[{ label: "프로젝트", to: "/projects" }, { label: `스캔 #${id}` }]} />
        <div className="panel"><Empty icon="alert" title={q.error.status === 404 ? "스캔을 찾을 수 없습니다" : "스캔을 불러오지 못했습니다"}
          description={q.error.status === 404 ? "없는 스캔이거나 이 프로젝트에 접근 권한이 없습니다." : q.error.message} /></div>
      </>
    );
  }

  const curIds = new Set(cur.data?.items.map((f) => f.id));
  const prevIds = new Set(prev.data?.items.map((f) => f.id));
  const lists = {
    new: (cur.data?.items ?? []).filter((f) => !prevIds.has(f.id)),
    fixed: (prev.data?.items ?? []).filter((f) => !curIds.has(f.id)),
    all: cur.data?.items ?? [],
  };
  const rows = lists[tab as keyof typeof lists];
  const listLoading = cur.isPending || (!!prevId && prev.isPending);

  return (
    <>
      <PageHeader title={`스캔 #${id}`}
        crumbs={[{ label: "프로젝트", to: "/projects" }, ...(project ? [{ label: project.name, to: `/projects/${project.key}/scans` }] : []), { label: `스캔 #${id}` }]}
        description={s && <span className="scan-target"><span className="tag tag-quiet">{TARGET_KIND_LABEL[s.target_kind] ?? s.target_kind}</span><span className="mono">{s.target_name}</span>{s.ref && <span className="mono muted">@ {s.ref}</span>}</span>}
        actions={s && (
          <>
            {live(s.status) && <Button variant="danger" loading={cancel.isPending} onClick={() => confirm("이 스캔을 취소할까요?") && cancel.mutate()}>스캔 취소</Button>}
            {s.has_raw && <a className="btn btn-secondary" href={`${API_BASE}/scans/${s.id}/raw`} download><Icon name="fileText" />원본 보고서</a>}
          </>
        )} />

      {s && <PolicyBanner s={s} />}

      <div className="detail-grid">
        <div className="detail-main">
          <section className="panel" aria-labelledby="h-sum">
            <div className="panel-head"><h2 id="h-sum">요약</h2><span className="panel-meta">이 스캔 직후 대상의 열린 결과</span></div>
            <SevTiles c={s?.summary} />
          </section>

          {done && (
            <section className="panel" aria-labelledby="h-diff">
              <div className="panel-head">
                <h2 id="h-diff">이전 스캔 대비</h2>
                <span className="panel-meta">{prevId ? <>같은 대상·형식의 <Link to={`/scans/${prevId}`}>스캔 #{prevId}</Link>과 비교</> : "같은 대상의 이전 스캔이 없어 모두 새 결과로 봅니다"}</span>
              </div>
              <div className="diff-stats">
                <Stat n={s.diff.new} label="새로 발견" tone={s.diff.new ? "danger" : undefined} />
                <Stat n={s.diff.fixed} label="이번에 사라짐" tone={s.diff.fixed ? "ok" : undefined} />
                <Stat n={s.diff.unchanged} label="그대로" />
              </div>
              <div className="panel-tabs">
                <Tabs label="비교 목록" value={tab} onChange={setTab} tabs={[
                  { id: "new", label: "새로 발견", count: s.diff.new },
                  { id: "fixed", label: "사라짐", count: s.diff.fixed },
                  { id: "all", label: "이 스캔의 전체 결과", count: s.diff.new + s.diff.unchanged },
                ]} />
              </div>
              <div role="tabpanel" id={`tabpanel-${tab}`} aria-labelledby={`tab-${tab}`}>
                {(cur.data?.truncated || prev.data?.truncated) && <p className="side-note" style={{ padding: "0 18px 10px" }}>결과가 많아 앞의 {fmtNumber(MAX_ROWS)}건만 비교했습니다.</p>}
                <Table<Finding> caption="결과" rows={rows} rowKey={(f) => f.id} loading={listLoading} dense onRowClick={setOpen} maxHeight={560}
                  empty={<Empty compact icon={tab === "new" ? "shieldCheck" : "inbox"} title={tab === "new" ? "새로 발견된 결과가 없습니다" : tab === "fixed" ? "사라진 결과가 없습니다" : "이 스캔에는 결과가 없습니다"} />}
                  columns={[
                    { key: "sev", header: "심각도", width: 92, render: (f) => <SeverityBadge severity={f.severity} /> },
                    { key: "rule", header: "취약점", render: (f) => (
                      <span className="rule">
                        {f.kind === "vuln" ? <Link to={`/vulns/${encodeURIComponent(f.rule_id)}`} className="mono">{f.rule_id}</Link> : <span className="mono">{f.rule_id}</span>}
                        {f.title && <span className="rule-title" title={f.title}>{f.title}</span>}
                      </span>) },
                    { key: "pkg", header: "패키지 · 조치 버전", width: "30%", render: (f) => (f.pkg_name ? <PkgCell name={f.pkg_name} version={f.pkg_version} fixed={f.fixed_version} /> : <span className="mono muted break">{f.location || "—"}</span>) },
                    { key: "status", header: "현재 상태", width: 100, render: (f) => <StatusBadge status={f.status} /> },
                  ]} />
              </div>
            </section>
          )}
        </div>

        <aside className="detail-side">
          <section className="panel" aria-labelledby="h-info">
            <div className="panel-head"><h2 id="h-info">정보</h2></div>
            <div className="panel-body">
              {!s ? <span className="skeleton skeleton-block" style={{ height: 160 }} /> : (
                <dl className="kv kv-tight">
                  <div className="kv-row"><dt>상태</dt><dd><StatusBadge status={s.status} /></dd></div>
                  {project && <div className="kv-row"><dt>프로젝트</dt><dd><Link to={`/projects/${project.key}`}>{project.name}</Link></dd></div>}
                  <div className="kv-row"><dt>방식</dt><dd>{SOURCE_LABEL[s.source] ?? s.source}</dd></div>
                  <div className="kv-row"><dt>형식</dt><dd className="mono">{s.format}</dd></div>
                  {s.summary.os?.name && <div className="kv-row"><dt>OS</dt><dd>{s.summary.os.family} {s.summary.os.name}</dd></div>}
                  <div className="kv-row"><dt>올린 주체</dt><dd>{s.created_by_token ? `API 토큰 #${s.created_by_token}` : s.created_by_user ? `사용자 #${s.created_by_user}` : "시스템"}</dd></div>
                  <div className="kv-row"><dt>시작</dt><dd>{fmtDateTime(s.created_at)}</dd></div>
                  <div className="kv-row"><dt>완료</dt><dd>{fmtDateTime(s.finished_at)}</dd></div>
                  {!s.has_raw && done && <div className="kv-row"><dt>원본</dt><dd className="muted">보존 기간이 지나 삭제됨</dd></div>}
                </dl>
              )}
            </div>
          </section>
        </aside>
      </div>
      <FindingDrawer finding={open} onClose={() => setOpen(null)} />
    </>
  );
}

function PolicyBanner({ s }: { s: ScanDetail }) {
  if (s.status === "failed") return <div className="alert alert-danger" role="alert"><Icon name="alert" /><span><b>스캔 실패</b> · {s.error || "원인을 알 수 없습니다."}</span></div>;
  if (s.status === "canceled") return <div className="alert alert-warn"><Icon name="info" />취소된 스캔입니다.</div>;
  if (live(s.status)) return <div className="alert alert-info" role="status"><span className="spinner" aria-hidden="true" />{s.status === "queued" ? "스캔 대기 중입니다." : "스캔 중입니다."} 끝나면 자동으로 갱신됩니다.</div>;
  if (!s.policy) return <div className="alert alert-info"><Icon name="info" />정책 판정 결과가 없습니다.</div>;
  return s.policy.passed ? (
    <div className="policy-banner policy-banner-pass"><Icon name="shieldCheck" size={20} /><div><b>정책 통과</b><p>CI에서 이 스캔은 성공으로 끝났습니다.</p></div></div>
  ) : (
    <div className="policy-banner policy-banner-fail" role="alert">
      <Icon name="alert" size={20} />
      <div>
        <b>정책 실패</b>
        <ul>{(s.policy.reasons?.length ? s.policy.reasons : [s.policy.error || "사유가 기록되지 않았습니다."]).map((r, i) => <li key={i}>{r}</li>)}</ul>
      </div>
    </div>
  );
}

function SevTiles({ c }: { c?: Partial<Counts> }) {
  return (
    <ul className="sev-tiles">
      {SEVERITIES.map((sev) => {
        const n = c ? c[sev.toLowerCase() as keyof Counts] ?? 0 : undefined;
        return (
          <li key={sev} className={n === 0 ? "is-zero" : undefined}>
            <span className="risk-label"><span className={`sev-dot dot-${sev.toLowerCase()}`} aria-hidden="true" />{SEVERITY_LABEL[sev]}</span>
            <span className="risk-n num">{n === undefined ? "–" : fmtNumber(n)}</span>
          </li>
        );
      })}
    </ul>
  );
}

function Stat({ n, label, tone }: { n: number; label: string; tone?: "danger" | "ok" }) {
  return <div className={`stat${tone ? ` stat-${tone}` : ""}`}><span className="stat-n num">{fmtNumber(n)}</span><span className="stat-label">{label}</span></div>;
}
