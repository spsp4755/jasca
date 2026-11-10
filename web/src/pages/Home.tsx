import { Link, useNavigate } from "react-router-dom";
import { useDashboard } from "../api/hooks";
import { SEVERITIES, type Counts, type Dashboard, type FindingOrigin, type PolicyResult } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import Table from "../components/Table";
import TrendChart from "../components/TrendChart";
import { RESOLUTION_LABEL, SCOPE_LABEL, SEVERITY_LABEL, SOURCE_LABEL, daysSince, daysUntil, fmtDate, fmtDateTime, fmtNumber, fmtRelative } from "../lib/format";
import { exceptionWhat } from "./Exceptions";

// why a finding turned up without a new scan, for 새로 알려진 취약점
const FOUND_BY: Record<FindingOrigin, string> = { scan: "스캔에서 발견", recheck: "재평가로 발견", advisory: "사내 Advisory로 발견" };

export default function Home() {
  const q = useDashboard();
  return (
    <>
      <PageHeader title="홈" description="볼 수 있는 모든 프로젝트의 위험 요약입니다."
        actions={
          <>
            {q.dataUpdatedAt > 0 && <span className="page-meta" title={fmtDateTime(new Date(q.dataUpdatedAt).toISOString())}>{fmtRelative(new Date(q.dataUpdatedAt).toISOString())} 갱신</span>}
            <Link to="/scan" className="btn btn-primary"><Icon name="scan" />스캔하기</Link>
          </>
        } />
      {q.isError ? (
        <div className="alert alert-danger" role="alert">
          <Icon name="alert" />요약을 불러오지 못했습니다. {q.error.message}
          <Button size="sm" onClick={() => q.refetch()} className="alert-action">다시 시도</Button>
        </div>
      ) : (
        <HomeBody d={q.data} loading={q.isPending} />
      )}
    </>
  );
}

/** Before the first scan the dashboard would be six empty boxes; say what to do instead. */
function FirstRun() {
  return (
    <section className="panel first-run" aria-labelledby="h-first">
      <h2 id="h-first">아직 스캔한 것이 없습니다</h2>
      <p>검사할 파일만 있으면 시작할 수 있습니다. 프로젝트 폴더를 압축한 파일이나 컨테이너 이미지 tar를 올리면 취약점, 비밀값, 설정 오류를 찾아 심각도별로 정리해 보여 줍니다.</p>
      <div className="first-run-actions">
        <Link to="/scan" className="btn btn-primary"><Icon name="scan" />첫 스캔 하기</Link>
      </div>
    </section>
  );
}

function HomeBody({ d, loading }: { d?: Dashboard; loading: boolean }) {
  const navigate = useNavigate();
  if (d && !d.recent_scans.length && !d.totals.open) return <FirstRun />;
  return (
    <div className="home-grid">
      <RiskSummary totals={d?.totals} />

      <section className="panel span-8" aria-labelledby="h-trend">
        <div className="panel-head">
          <h2 id="h-trend">최근 30일 추세</h2>
          <span className="panel-meta">날짜별 열린 결과</span>
        </div>
        <div className="panel-body">
          {d ? (d.trend.length ? <TrendChart data={d.trend} /> : <Empty compact icon="chart" title="추세 데이터가 없습니다" description="스캔 결과가 쌓이면 날짜별 변화가 표시됩니다." />)
            : <div className="skeleton skeleton-block" style={{ height: 268 }} />}
        </div>
      </section>

      <section className="panel span-4" aria-labelledby="h-exp">
        <div className="panel-head">
          <h2 id="h-exp">만료 임박 예외</h2>
          <Link to="/exceptions" className="panel-link">전체 <Icon name="chevronRight" size={14} /></Link>
        </div>
        {!d ? <ListSkeleton /> : d.expiring_exceptions.length === 0 ? (
          <Empty compact icon="shield" title="14일 안에 만료되는 예외가 없습니다" />
        ) : (
          <ul className="list">
            {d.expiring_exceptions.map((x) => {
              const left = Math.max(0, daysUntil(x.expires_at));
              return (
                <li key={x.id} className="list-row">
                  <div className="list-main">
                    <Link className="mono" to={`/exceptions?id=${x.id}`}>{exceptionWhat(x)}</Link>
                    <span className="list-sub">{x.project_key ?? "전사"} · {SCOPE_LABEL[x.scope]} · {RESOLUTION_LABEL[x.resolution]}</span>
                  </div>
                  <span className={`due${left <= 3 ? " due-soon" : ""}`} title={fmtDate(x.expires_at)}>
                    {left <= 0 ? "오늘 만료" : `D-${left}`}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="panel span-7" aria-labelledby="h-old">
        <div className="panel-head">
          <h2 id="h-old">오래 열린 CRITICAL 결과</h2>
          <Link to="/findings?severity=CRITICAL&status=open" className="panel-link">전체 <Icon name="chevronRight" size={14} /></Link>
        </div>
        <Table caption="오래 열린 CRITICAL 결과" loading={loading} rows={d?.oldest_critical ?? []} rowKey={(r) => r.id} dense
          empty={<Empty compact icon="shieldCheck" title="열린 CRITICAL 결과가 없습니다" />}
          columns={[
            { key: "rule", header: "취약점", width: 150, nowrap: true, render: (r) => <Link to={`/findings?finding=${r.id}`} className="mono">{r.rule_id}</Link> }, // may be a secret or misconfig, not a CVE
            { key: "pkg", header: "패키지 · 위치", render: (r) => (r.pkg_name ? <PkgCell name={r.pkg_name} version={r.pkg_version} fixed={r.fixed_version} /> : <span className="mono muted break">{r.location || "—"}</span>) },
            { key: "where", header: "프로젝트 · 대상", render: (r) => <ProjectTarget project={r.project_key} target={r.target} /> },
            { key: "age", header: "열린 기간", align: "right", width: 84, render: (r) => <span className="num age" title={fmtDate(r.first_seen_at)}>{daysSince(r.first_seen_at)}일</span> },
          ]} />
      </section>

      <section className="panel span-5" aria-labelledby="h-new">
        <div className="panel-head">
          <h2 id="h-new">새로 알려진 취약점</h2>
          <span className="panel-meta">최근 7일 · 재평가와 사내 Advisory</span>
        </div>
        {!d ? <ListSkeleton /> : d.newly_known.length === 0 ? (
          <Empty compact icon="megaphone" title="최근 7일 동안 새로 알려진 취약점이 없습니다" description="Trivy DB가 갱신되거나 사내 Advisory가 등록되면 기존 대상에서 새로 찾은 결과가 여기에 나옵니다." />
        ) : (
          <ul className="list">
            {d.newly_known.map((f) => (
              <li key={f.id} className="list-row">
                <SeverityBadge severity={f.severity} />
                <div className="list-main">
                  <Link to={`/vulns/${encodeURIComponent(f.rule_id)}`} className="mono">{f.rule_id}</Link>
                  <span className="list-sub" title={`${f.target} · ${f.pkg_name} ${f.pkg_version}`}>{f.project_key} · {f.target} · {f.pkg_name} {f.pkg_version}</span>
                </div>
                <span className="tag tag-quiet">{FOUND_BY[f.origin] ?? f.origin}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel span-12" aria-labelledby="h-scans">
        <div className="panel-head">
          <h2 id="h-scans">최근 스캔</h2>
          <Link to="/projects" className="panel-link">프로젝트 <Icon name="chevronRight" size={14} /></Link>
        </div>
        <Table caption="최근 스캔" loading={loading} rows={d?.recent_scans ?? []} rowKey={(r) => r.id} dense
          onRowClick={(r) => navigate(`/scans/${r.id}`)}
          empty={<Empty compact icon="scan" title="아직 스캔이 없습니다" description="파일을 올려 서버에서 스캔하거나, CI에서 Trivy 결과를 업로드하세요."
            action={<Link to="/scan" className="btn btn-secondary btn-sm">스캔하기</Link>} />}
          columns={[
            { key: "where", header: "프로젝트 · 대상", render: (r) => <ProjectTarget project={r.project_key} target={r.target} /> },
            { key: "source", header: "방식", width: 96, render: (r) => <span className="muted nw">{SOURCE_LABEL[r.source] ?? r.source}</span> },
            { key: "status", header: "상태", width: 96, render: (r) => <StatusBadge status={r.status} /> },
            { key: "summary", header: "결과", width: 260, render: (r) => <SummaryCell s={r.summary} /> },
            { key: "policy", header: "정책", width: 84, render: (r) => <PolicyCell s={r} /> },
            { key: "at", header: "시각", width: 128, align: "right", render: (r) => <span className="muted" title={fmtDateTime(r.created_at)}>{fmtRelative(r.created_at)}</span> },
          ]} />
      </section>
    </div>
  );
}

function RiskSummary({ totals }: { totals?: Counts }) {
  const sevs = SEVERITIES.map((s) => ({ s, n: totals ? totals[s.toLowerCase() as keyof Counts] : 0 }));
  const sum = sevs.reduce((a, x) => a + x.n, 0);
  return (
    <section className="panel span-12 risk" aria-labelledby="h-risk">
      <div className="risk-total">
        <h2 id="h-risk">열린 결과</h2>
        <p className="risk-big num">{totals ? fmtNumber(totals.open) : <span className="skeleton" style={{ width: 72, height: 30 }} />}</p>
        <p className="risk-caption">
          {totals ? (totals.critical + totals.high > 0 ? <Link to="/findings?severity=CRITICAL,HIGH">CRITICAL·HIGH <b className="num">{fmtNumber(totals.critical + totals.high)}</b>건 먼저 확인하세요</Link> : "CRITICAL·HIGH 없음") : " "}
        </p>
      </div>
      <div className="risk-right">
        <ul className="risk-tiles">
          {sevs.map(({ s, n }) => (
            <li key={s}>
              <Link to={`/findings?severity=${s}&status=open`} className={`risk-tile${n === 0 ? " is-zero" : ""}`}>
                <span className="risk-label"><span className={`sev-dot dot-${s.toLowerCase()}`} aria-hidden="true" />{SEVERITY_LABEL[s]}</span>
                <span className="risk-n num">{totals ? fmtNumber(n) : "–"}</span>
              </Link>
            </li>
          ))}
        </ul>
        <div className="risk-bar" role="img" aria-label={sum ? sevs.map(({ s, n }) => `${SEVERITY_LABEL[s]} ${n}건`).join(", ") : "열린 결과 없음"}>
          {sum > 0 && sevs.map(({ s, n }) => n > 0 && <span key={s} className={`bar-${s.toLowerCase()}`} style={{ flexGrow: n }} />)}
        </div>
      </div>
    </section>
  );
}

export function PkgCell({ name, version, fixed }: { name: string; version: string; fixed: string }) {
  return (
    <span className="pkg">
      <span className="pkg-name">{name || "—"}</span>
      {version && <span className="mono pkg-ver">{version}</span>}
      {fixed ? <span className="mono pkg-fix" title="조치 버전">→ {fixed}</span> : <span className="pkg-nofix">조치 버전 없음</span>}
    </span>
  );
}

export function ProjectTarget({ project, target }: { project: string; target: string }) {
  return (
    <span className="pt">
      <Link to={`/projects/${encodeURIComponent(project)}`} className="pt-project">{project}</Link>
      <span className="pt-target mono" title={target}>{target}</span>
    </span>
  );
}

export function SummaryCell({ s }: { s: Partial<Counts> }) {
  const parts = SEVERITIES.map((sev) => [sev, s[sev.toLowerCase() as keyof Counts] ?? 0] as const).filter(([, n]) => n > 0);
  if (!parts.length) return <span className="muted">없음</span>;
  return <span className="sev-row">{parts.map(([sev, n]) => <SeverityBadge key={sev} severity={sev} count={n} compact />)}</span>;
}

export function PolicyCell({ s }: { s: { policy: PolicyResult | null } }) {
  if (!s.policy) return <span className="muted">—</span>;
  if (s.policy.disabled) return <span className="muted nw" title="정책 사용 안 함: 이 스캔은 정책으로 판정하지 않았습니다.">사용 안 함</span>;
  return s.policy.passed
    ? <span className="policy policy-pass"><Icon name="check" size={14} />통과</span>
    : <span className="policy policy-fail" title={s.policy.reasons.join("\n")}><Icon name="x" size={14} />실패</span>;
}

function ListSkeleton() {
  return (
    <ul className="list" aria-hidden="true">
      {[0, 1, 2].map((i) => <li key={i} className="list-row"><span className="skeleton" style={{ width: `${80 - i * 15}%` }} /></li>)}
    </ul>
  );
}
