import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { API_BASE, qs } from "../api/client";
import { isSecurity, useApi, useMe } from "../api/hooks";
import type { PackageHit, PackageSearch, Project } from "../api/types";
import Button from "../components/Button";
import Empty from "../components/Empty";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import Table, { type Column } from "../components/Table";
import { fmtDate, fmtDateTime, fmtNumber } from "../lib/format";
import { ProjectTarget } from "./Home";

const EXAMPLES = [{ q: "log4j-core", version: "<2.17.1" }, { q: "openssl", version: "" }, { q: "spring-core", version: "" }];
const ADVISORY_MAX = 10; // more packages than this is not one advisory: narrow the search first

const columns: Column<PackageHit>[] = [
  {
    key: "name", header: "패키지 · 종류", width: "27%", render: (r) => (
      <span className="pkg-hit"><span className="pkg-name">{r.name}</span>{r.ecosystem && <span className="tag tag-quiet">{r.ecosystem}</span>}</span>
    ),
  },
  { key: "version", header: "버전", width: "12%", render: (r) => <span className="mono pkg-wrap">{r.version}</span> },
  { key: "where", header: "프로젝트 · 대상", width: "21%", nowrap: true, render: (r) => <ProjectTarget project={r.project_key} target={r.target_name} /> }, // nowrap + width: cut with an ellipsis
  {
    key: "paths", header: "위치", width: "20%", render: (r) => (r.path_count === 0 ? <span className="muted">—</span> : (
      <span className="pkg-paths">
        <span className="mono pkg-wrap pkg-path" title={r.paths.join("\n")}>{r.paths[0]}</span>
        {r.path_count > 1 && <span className="muted nw">외 {fmtNumber(r.path_count - 1)}곳</span>}
      </span>
    )),
  },
  {
    key: "open", header: "열린 취약점", width: 100, render: (r) => (r.open_findings === 0 || !r.worst_severity ? <span className="muted">없음</span> : (
      <Link className="pkg-open" to={`/projects/${encodeURIComponent(r.project_key)}/findings${qs({ q: r.name, target_id: r.target_id })}`}
        aria-label={`열린 취약점 ${r.open_findings}건, 가장 높은 심각도 ${r.worst_severity}`}>
        <SeverityBadge severity={r.worst_severity} compact /><span className="num">{fmtNumber(r.open_findings)}건</span>
      </Link>
    )),
  },
  { key: "scan", header: "기준 스캔", width: 108, render: (r) => <Link to={`/scans/${r.scan_id}`} className="num nw" title={`${fmtDateTime(r.scan_at)} 스캔의 패키지 목록`}>{fmtDate(r.scan_at)}</Link> },
];

export default function Packages() {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const f = { q: (sp.get("q") ?? "").trim(), version: (sp.get("version") ?? "").trim(), ecosystem: sp.get("ecosystem") ?? "", project: sp.get("project") ?? "" };
  const [text, setText] = useState(f.q);
  const [ver, setVer] = useState(f.version);
  useEffect(() => { setText(f.q); setVer(f.version); }, [f.q, f.version]);
  const [short, setShort] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  // Layout moves focus to the page heading after a navigation; this page is a search box first, so take it back.
  useEffect(() => { const id = requestAnimationFrame(() => input.current?.focus()); return () => cancelAnimationFrame(id); }, []);

  const ready = [...f.q].length >= 2;
  const query = qs(f);
  const res = useApi<PackageSearch>(ready ? `/packages${query}` : null, { placeholderData: (prev) => prev });
  const projects = useApi<Project[]>("/projects").data ?? [];
  const sec = isSecurity(useMe().data);

  // a new search is a history entry (Back returns to the previous one); the two selects only narrow it
  const search = (q: string, version: string) => {
    if ([...q.trim()].length < 2) { setShort(true); input.current?.focus(); return; }
    setShort(false);
    const next = new URLSearchParams();
    next.set("q", q.trim());
    if (version.trim()) next.set("version", version.trim());
    if (f.project) next.set("project", f.project);
    setSp(next);
  };
  const narrow = (k: "ecosystem" | "project", v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v); else next.delete(k);
    setSp(next, { replace: true });
  };
  const onSubmit = (e: FormEvent) => { e.preventDefault(); search(text, ver); };

  const d = ready ? res.data : undefined;
  const items = d?.items ?? [];
  const matched = items.filter((r) => !r.version_unknown);
  const unknown = items.filter((r) => r.version_unknown);
  const t = d?.totals;
  const ecos = [...new Set([...(d?.ecosystems ?? []), ...(f.ecosystem ? [f.ecosystem] : [])])].sort();
  const pkgs = [...new Set(items.map((r) => `${r.ecosystem}:${r.name}`))];
  const advisory = () => {
    const p = new URLSearchParams();
    for (const k of pkgs) p.append("pkg", k);
    if (f.version) p.set("range", f.version);
    nav(`/advisories/new?${p}`);
  };
  const notSearched = t && t.targets_without_inventory > 0
    ? `대상 ${fmtNumber(t.targets_without_inventory)}개는 패키지 목록이 없어 찾지 못합니다` : "";
  const rowKey = (r: PackageHit) => `${r.target_id}|${r.ecosystem}|${r.name}|${r.version}`;

  return (
    <div className="packages">
      <PageHeader title="패키지 찾기" description="어떤 패키지를 어느 프로젝트에서, 어떤 버전으로 쓰는지 찾습니다. 취약점이 아직 알려지지 않은 패키지도 찾을 수 있습니다." />
      <form className="filterbar pkg-search" role="search" aria-label="패키지 찾기" onSubmit={onSubmit}>
        <div className="filter-q pkg-q">
          <Icon name="search" />
          <input ref={input} className="input" type="search" placeholder="패키지 이름 (예: log4j-core)" aria-label="패키지 이름" value={text} maxLength={200}
            autoFocus aria-invalid={short || undefined} aria-describedby={short ? "pkg-short" : undefined} onChange={(e) => { setText(e.target.value); setShort(false); }} />
        </div>
        <input className="input mono pkg-ver" placeholder="버전 조건 (예: <2.17.1)" aria-label="버전 조건" aria-describedby="pkg-hint" value={ver} maxLength={200}
          onChange={(e) => setVer(e.target.value)} />
        <select className="input" aria-label="패키지 종류" value={f.ecosystem} onChange={(e) => narrow("ecosystem", e.target.value)}>
          <option value="">모든 종류</option>
          {ecos.map((e) => <option key={e} value={e}>{e}</option>)}
        </select>
        {projects.length > 1 && (
          <select className="input" aria-label="프로젝트" value={f.project} onChange={(e) => narrow("project", e.target.value)}>
            <option value="">모든 프로젝트</option>
            {projects.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
          </select>
        )}
        <Button type="submit" variant="primary" size="sm" loading={ready && res.isFetching}>찾기</Button>
      </form>
      {short && <p id="pkg-short" className="field-err pkg-hint" role="alert">패키지 이름을 2자 이상 입력하세요.</p>}
      <p id="pkg-hint" className="field-hint pkg-hint">
        이름의 일부만 써도 됩니다. 버전 조건은 <span className="mono">&lt;2.17.1</span>, <span className="mono">&gt;=2.0 &lt;2.17.1</span>처럼 쓰고,
        {" "}<span className="mono">2.14.1</span>처럼 버전만 쓰면 정확히 그 버전을 찾습니다. 비워 두면 모든 버전을 찾습니다.
      </p>

      {!ready ? (
        <div className="panel">
          <Empty icon="search" title="찾을 패키지 이름을 입력하세요"
            description="새 취약점이 발표된 날, 취약점 DB에 아직 없어도 스캔할 때 저장해 둔 패키지 목록에서 바로 찾습니다. 대상마다 가장 최근 스캔의 패키지 목록을 봅니다."
            action={EXAMPLES.map((e) => (
              <Button key={e.q} size="sm" className="mono" onClick={() => { setText(e.q); setVer(e.version); search(e.q, e.version); }}>{e.q}{e.version && ` ${e.version}`}</Button>
            ))} />
        </div>
      ) : res.isError ? (
        <div className="alert alert-danger" role="alert"><Icon name="alert" />{res.error.message}
          {res.error.status !== 400 && <Button size="sm" className="alert-action" onClick={() => res.refetch()}>다시 시도</Button>}</div>
      ) : !d || !t ? (
        <div className="panel"><Table caption="패키지 목록" rows={[]} rowKey={rowKey} columns={columns} loading dense /></div>
      ) : items.length === 0 ? (
        <div className="panel">
          {t.targets_searched === 0 ? (
            <Empty icon="inbox" title="찾아볼 패키지 목록이 아직 없습니다"
              description={`패키지 목록은 이미지·저장소를 스캔하거나 Trivy·CycloneDX 결과를 올릴 때 저장됩니다.${notSearched ? ` ${notSearched}.` : ""}`}
              action={<Link className="btn btn-secondary btn-sm" to="/scan">스캔하기</Link>} />
          ) : (
            <Empty icon="search" title={`"${f.q}"에 맞는 패키지를 찾지 못했습니다`}
              description={`패키지 목록이 있는 대상 ${fmtNumber(t.targets_searched)}개의 가장 최근 스캔에서 찾았습니다.${notSearched ? ` ${notSearched}.` : ""} 이름의 일부만 넣거나 조건을 빼고 다시 찾아 보세요.`}
              action={(f.version || f.ecosystem || f.project) ? <Button size="sm" onClick={() => setSp(new URLSearchParams({ q: f.q }))}>이름만으로 다시 찾기</Button> : undefined} />
          )}
        </div>
      ) : (
        <>
          <div className="result-bar">
            <span className="result-count" aria-live="polite">
              프로젝트 <b className="num">{fmtNumber(t.projects)}</b>개 · 대상 <b className="num">{fmtNumber(t.targets)}</b>개에서 <b className="num">{fmtNumber(t.matched)}</b>건
              {t.version_unknown > 0 && <> · 버전을 비교하지 못함 <b className="num">{fmtNumber(t.version_unknown)}</b>건</>}
              {notSearched && <span className="muted"> · {notSearched}</span>}
            </span>
            <span className="pkg-actions">
              {sec && (
                <Button size="sm" icon="megaphone" disabled={pkgs.length > ADVISORY_MAX} onClick={advisory}
                  title={pkgs.length > ADVISORY_MAX ? `패키지가 ${ADVISORY_MAX}종을 넘습니다. 이름을 더 정확히 입력한 뒤 등록하세요.` : "찾은 패키지와 버전 조건을 채운 새 Advisory 화면을 엽니다."}>사내 Advisory로 등록</Button>
              )}
              <a className="btn btn-secondary btn-sm" href={`${API_BASE}/packages.csv${query}`} download><Icon name="table" size={14} />CSV 내려받기</a>
            </span>
          </div>
          {d.truncated && (
            <div className="alert alert-warn" role="status"><Icon name="alert" />
              결과가 많아 처음 {fmtNumber(items.length)}건만 보여 줍니다. 이름을 더 길게 쓰거나 버전 조건·프로젝트로 좁혀 보세요.</div>
          )}
          {matched.length > 0 && (
            <div className="panel">
              <Table caption="찾은 패키지" rows={matched} rowKey={rowKey} columns={columns} dense />
            </div>
          )}
          {matched.length === 0 && unknown.length > 0 && (
            <div className="alert alert-info" role="status"><Icon name="info" />조건에 맞는다고 확인된 패키지는 없습니다. 아래 패키지는 버전을 비교하지 못했으니 직접 확인하세요.</div>
          )}
          {unknown.length > 0 && (
            <section className="panel pkg-unknown" aria-labelledby="pkg-unknown-h">
              <div className="panel-head">
                <h2 id="pkg-unknown-h">버전을 비교하지 못함</h2>
                <span className="panel-meta">버전 표기가 달라 조건 <span className="mono">{f.version}</span>에 맞는지 알 수 없습니다. 영향이 있는지 직접 확인하세요.</span>
              </div>
              <Table caption="버전을 비교하지 못한 패키지" rows={unknown} rowKey={rowKey} columns={columns} dense />
            </section>
          )}
        </>
      )}
    </div>
  );
}
