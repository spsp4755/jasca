import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { SEVERITIES, type FindingFilters, type Project, type Target } from "../api/types";
import { KIND_LABEL, ORIGIN_LABEL, SEVERITY_LABEL, TARGET_KIND_LABEL } from "../lib/format";
import Button from "./Button";
import Icon from "./Icon";
import { statusLabel } from "./StatusBadge";

const STATUSES = ["open", "fixed", "accepted", "false_positive"];
const KEYS = ["project", "target_id", "severity", "status", "kind", "origin", "fixable", "q"] as const;

/**
 * Findings filters live in the URL, under the API's own parameter names. A missing `status` means "open" (what people
 * look at daily); `status=` (empty) means every status.
 */
export function readFilters(sp: URLSearchParams): FindingFilters {
  const f: FindingFilters = {};
  for (const k of KEYS) { const v = sp.get(k); if (v) (f as Record<string, string>)[k] = v; }
  if (!sp.has("status")) f.status = "open";
  return f;
}

const list = (v?: string) => (v ? v.split(",") : []);

export default function FilterBar({ projects, targets }: {
  /** Project choices; omit inside a project page. */
  projects?: Project[];
  /** Target choices for the current project; omit to show a removable chip when target_id is set. */
  targets?: Target[];
}) {
  const [sp, setSp] = useSearchParams();
  const f = readFilters(sp);
  const [text, setText] = useState(f.q ?? "");
  useEffect(() => setText(f.q ?? ""), [f.q]);
  const set = (k: string, v: string | undefined) => {
    const next = new URLSearchParams(sp);
    if (v === undefined || (v === "" && k !== "status")) next.delete(k); else next.set(k, v);
    setSp(next, { replace: true });
  };
  const sev = list(f.severity);
  const toggleSev = (s: string) => set("severity", (sev.includes(s) ? sev.filter((x) => x !== s) : [...sev, s]).sort((a, b) => SEVERITIES.indexOf(a as never) - SEVERITIES.indexOf(b as never)).join(","));
  const dirty = KEYS.some((k) => k !== "status" && sp.has(k)) || f.status !== "open";
  const target = f.target_id && !targets ? f.target_id : undefined;
  return (
    <div className="filterbar" role="search" aria-label="결과 필터">
      <form className="filter-q" onSubmit={(e) => { e.preventDefault(); set("q", text.trim()); }}>
        <Icon name="search" />
        <input className="input" type="search" placeholder="CVE, 패키지, 제목으로 찾기" aria-label="검색어" value={text} maxLength={200}
          onChange={(e) => setText(e.target.value)} onBlur={() => text.trim() !== (f.q ?? "") && set("q", text.trim())} />
      </form>
      <div className="sev-toggles" role="group" aria-label="심각도">
        {SEVERITIES.map((s) => (
          <button key={s} type="button" aria-pressed={sev.includes(s)} className={`sev-toggle st-${s.toLowerCase()}`} onClick={() => toggleSev(s)} title={s}>
            <span className={`sev-dot dot-${s.toLowerCase()}`} aria-hidden="true" />{SEVERITY_LABEL[s]}
          </button>
        ))}
      </div>
      <select className="input" aria-label="상태" value={list(f.status).length === 1 ? f.status : ""} onChange={(e) => set("status", e.target.value)}>
        <option value="">모든 상태</option>
        {STATUSES.map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
      </select>
      {projects && (
        <select className="input" aria-label="프로젝트" value={f.project ?? ""} onChange={(e) => set("project", e.target.value)}>
          <option value="">모든 프로젝트</option>
          {projects.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
        </select>
      )}
      {targets && targets.length > 0 && (
        <select className="input" aria-label="대상" value={f.target_id ?? ""} onChange={(e) => set("target_id", e.target.value)}>
          <option value="">모든 대상</option>
          {targets.map((t) => <option key={t.id} value={t.id}>{TARGET_KIND_LABEL[t.kind]} · {t.name}</option>)}
        </select>
      )}
      <select className="input" aria-label="종류" value={f.kind ?? ""} onChange={(e) => set("kind", e.target.value)}>
        <option value="">모든 종류</option>
        {Object.entries(KIND_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      </select>
      <select className="input" aria-label="출처" value={f.origin ?? ""} onChange={(e) => set("origin", e.target.value)}>
        <option value="">모든 출처</option>
        {Object.entries(ORIGIN_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      </select>
      <label className="check-row filter-fix">
        <input type="checkbox" checked={f.fixable === "true"} onChange={(e) => set("fixable", e.target.checked ? "true" : undefined)} />조치 버전 있음
      </label>
      {target && (
        <span className="tag filter-chip">대상 #{target}
          <button type="button" aria-label="대상 필터 지우기" onClick={() => set("target_id", undefined)}><Icon name="x" size={12} /></button>
        </span>
      )}
      {dirty && <Button size="sm" variant="ghost" onClick={() => setSp(new URLSearchParams(), { replace: true })}>필터 초기화</Button>}
    </div>
  );
}
