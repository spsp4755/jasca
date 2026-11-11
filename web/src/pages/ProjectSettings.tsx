import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, type ApiError } from "../api/client";
import { useApi } from "../api/hooks";
import { SEVERITIES, type ApiToken, type Channel, type Member, type NotifySub, type Policy, type Project, type ProjectRole, type Severity } from "../api/types";
import Button from "../components/Button";
import CiSnippet from "../components/CiSnippet";
import Dialog from "../components/Dialog";
import Empty from "../components/Empty";
import Field from "../components/Field";
import Icon from "../components/Icon";
import PrincipalPicker, { principalKey } from "../components/PrincipalPicker";
import Table from "../components/Table";
import TokenDialog from "../components/TokenDialog";
import { useToast } from "../components/Toast";
import { copyText } from "../lib/clipboard";
import { ROLE_LABEL, SEVERITY_LABEL, daysUntil, fmtDate, fmtDateTime, fmtRelative } from "../lib/format";

const SECTIONS = [["general", "일반"], ["members", "멤버"], ["ci", "CI 연동"], ["tokens", "API 토큰"], ["mcp", "MCP 연동"], ["policy", "정책"], ["notify", "알림"], ["danger", "삭제"]] as const;
const OWNER_ONLY = new Set(["tokens", "danger"]);
const ROLES: ProjectRole[] = ["owner", "member", "viewer"];
const ROLE_HINT: Record<ProjectRole, string> = { owner: "설정 관리", member: "업로드·예외 요청", viewer: "조회만" };
export const NOTIFY_EVENTS: [string, string][] = [
  ["new_critical", "새 CRITICAL·HIGH 결과"], ["policy_failed", "정책 실패"], ["scan_failed", "스캔 실패"], ["new_known", "새로 알려진 취약점"],
  ["exception_requested", "예외 요청"], ["exception_approved", "예외 승인"], ["exception_rejected", "예외 반려"],
  ["exception_expiring", "예외 만료 임박"], ["exception_expired", "예외 만료"],
];

/** Mutation that toasts and invalidates the given GET paths. */
function useSave<V>(fn: (v: V) => Promise<unknown>, ok: string, invalidate: string[], onDone?: () => void) {
  const qc = useQueryClient();
  const toast = useToast();
  return useMutation<unknown, ApiError, V>({
    mutationFn: fn,
    onSuccess: () => { toast(ok, "ok"); invalidate.forEach((p) => qc.invalidateQueries({ queryKey: [p] })); onDone?.(); },
    onError: (e) => toast(e.message, "error"),
  });
}

export default function ProjectSettings({ project }: { project: Project }) {
  const owner = project.my_role === "owner";
  const loc = useLocation();
  useEffect(() => { if (loc.hash) document.getElementById(loc.hash.slice(1))?.scrollIntoView({ block: "start" }); }, [loc.hash]);
  return (
    <div className="settings">
      <nav className="settings-nav" aria-label="설정 항목">
        {SECTIONS.filter(([id]) => owner || !OWNER_ONLY.has(id)).map(([id, label]) => <a key={id} href={`#${id}`}>{label}</a>)}
      </nav>
      <div className="settings-main">
        {!owner && <div className="alert alert-info"><Icon name="info" />소유자만 설정을 바꿀 수 있습니다. 지금은 읽기 전용으로 보입니다.</div>}
        <General project={project} owner={owner} />
        <Members project={project} owner={owner} />
        <Section id="ci" title="CI 연동" meta="Trivy 결과를 CI에서 올리는 명령">
          <CiSnippet projectKey={project.key} />
        </Section>
        {owner && <Tokens project={project} />}
        <Mcp project={project} owner={owner} />
        <PolicyForm project={project} owner={owner} />
        <Notify project={project} owner={owner} />
        {owner && <Danger project={project} />}
      </div>
    </div>
  );
}

function Section({ id, title, meta, actions, children, tone }: { id: string; title: string; meta?: ReactNode; actions?: ReactNode; children: ReactNode; tone?: "danger" }) {
  return (
    <section id={id} className={`panel settings-sec${tone ? ` settings-${tone}` : ""}`} aria-labelledby={`h-${id}`}>
      <div className="panel-head">
        <h2 id={`h-${id}`}>{title}</h2>{meta && <span className="panel-meta">{meta}</span>}
        {actions && <span className="panel-actions">{actions}</span>}
      </div>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function General({ project, owner }: { project: Project; owner: boolean }) {
  const [name, setName] = useState(project.name);
  const [desc, setDesc] = useState(project.description);
  useEffect(() => { setName(project.name); setDesc(project.description); }, [project.name, project.description]);
  const save = useSave(() => api.patch(`/projects/${project.key}`, { name: name.trim(), description: desc.trim() }), "저장했습니다.", [`/projects/${project.key}`, "/projects"]);
  const nameErr = !name.trim() ? "이름을 입력하세요." : name.trim().length > 100 ? "100자 이하로 입력하세요." : undefined;
  const dirty = name.trim() !== project.name || desc.trim() !== project.description;
  return (
    <Section id="general" title="일반" meta={<>키 <span className="mono">{project.key}</span> · {fmtDate(project.created_at)} 생성</>}>
      <form className="form" onSubmit={(e) => { e.preventDefault(); if (!nameErr && dirty) save.mutate(undefined); }}>
        <Field label="이름" required error={nameErr}><input className="input" value={name} disabled={!owner} maxLength={100} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="설명" error={desc.length > 2000 ? "2000자 이하로 입력하세요." : undefined}>
          <textarea className="input" rows={3} value={desc} disabled={!owner} onChange={(e) => setDesc(e.target.value)} />
        </Field>
        {owner && <div className="form-actions"><Button type="submit" variant="primary" disabled={!dirty || !!nameErr || desc.length > 2000} loading={save.isPending}>저장</Button></div>}
      </form>
    </Section>
  );
}

function Members({ project, owner }: { project: Project; owner: boolean }) {
  const path = `/projects/${project.key}/members`;
  const q = useApi<Member[] | null>(path);
  const [list, setList] = useState<Member[] | null>(null);
  useEffect(() => setList(null), [q.data]);
  const rows = list ?? q.data ?? [];
  const save = useSave(() => api.put(path, rows.map(({ principal_kind, principal, role }) => ({ principal_kind, principal, role }))), "멤버를 저장했습니다.", [path]);
  const owners = rows.filter((m) => m.role === "owner").length;
  const edit = (next: Member[]) => setList(next);
  return (
    <Section id="members" title="멤버" meta="사용자 또는 Keycloak 그룹·부서 경로. 그룹은 하위 경로 사람까지 포함합니다."
      actions={owner && list && (
        <>
          <Button size="sm" variant="ghost" onClick={() => setList(null)}>되돌리기</Button>
          <Button size="sm" variant="primary" disabled={!owners} loading={save.isPending} onClick={() => save.mutate(undefined)}>변경 저장</Button>
        </>
      )}>
      {owner && (
        <div className="member-add">
          <PrincipalPicker taken={new Set(rows.map(principalKey))}
            onPick={(p) => edit([...rows, { principal_kind: p.kind, principal: p.principal, display: p.display, role: "member" }])} />
        </div>
      )}
      {owner && list && !owners && <div className="alert alert-warn" role="alert"><Icon name="alert" />소유자가 한 명(또는 한 그룹) 이상 있어야 저장할 수 있습니다.</div>}
      <Table<Member> caption="멤버" rows={rows} rowKey={principalKey} loading={q.isPending} dense
        empty={<Empty compact icon="folder" title="멤버가 없습니다" />}
        columns={[
          { key: "who", header: "이름", render: (m) => (
            <span className="member">
              <span className={`tag${m.principal_kind === "user" ? " tag-quiet" : ""}`}>{m.principal_kind === "user" ? "사용자" : "그룹"}</span>
              <span className={m.principal_kind === "group" ? "mono" : undefined}>{m.display || m.principal}</span>
            </span>) },
          { key: "role", header: "역할", width: 220, render: (m) => (owner ? (
            <select className="input input-sm" aria-label={`${m.display} 역할`} value={m.role}
              onChange={(e) => edit(rows.map((x) => (x === m ? { ...x, role: e.target.value as ProjectRole } : x)))}>
              {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]} · {ROLE_HINT[r]}</option>)}
            </select>
          ) : <span>{ROLE_LABEL[m.role]}</span>) },
          ...(owner ? [{ key: "rm", header: <span className="sr-only">삭제</span>, width: 48, align: "right" as const, render: (m: Member) => (
            <Button size="sm" variant="ghost" icon="x" aria-label={`${m.display} 빼기`} onClick={() => edit(rows.filter((x) => x !== m))} />) }] : []),
        ]} />
    </Section>
  );
}

function Tokens({ project }: { project: Project }) {
  const path = `/projects/${project.key}/tokens`;
  const q = useApi<ApiToken[] | null>(path);
  const [creating, setCreating] = useState(false);
  const revoke = useSave((id: number) => api.del(`${path}/${id}`), "토큰을 폐기했습니다.", [path]);
  const now = Date.now();
  const rows = [...(q.data ?? [])].sort((a, b) => Number(!!a.revoked_at) - Number(!!b.revoked_at) || b.id - a.id);
  return (
    <Section id="tokens" title="API 토큰" meta="CI 업로드와 조회용. 토큰 값은 만들 때 한 번만 보입니다."
      actions={<Button size="sm" variant="primary" icon="key" onClick={() => setCreating(true)}>토큰 만들기</Button>}>
      <Table<ApiToken> caption="API 토큰" rows={rows} rowKey={(t) => t.id} loading={q.isPending} dense
        empty={<Empty compact icon="key" title="토큰이 없습니다" description="CI에서 결과를 올리려면 업로드 권한 토큰을 만드세요." />}
        columns={[
          { key: "name", header: "이름", render: (t) => <span className="token-name"><b>{t.name}</b><span className="mono muted">{t.prefix}…</span></span> },
          { key: "scopes", header: "권한", width: 120, render: (t) => <span className="tags">{t.scopes.map((s) => <span key={s} className="tag tag-quiet">{s === "upload" ? "업로드" : "읽기"}</span>)}</span> },
          { key: "used", header: "마지막 사용", width: 110, render: (t) => <span className="muted" title={fmtDateTime(t.last_used_at)}>{t.last_used_at ? fmtRelative(t.last_used_at) : "없음"}</span> },
          { key: "exp", header: "만료", width: 120, render: (t) => {
            if (t.revoked_at) return <span className="muted" title={fmtDateTime(t.revoked_at)}>폐기됨</span>;
            if (new Date(t.expires_at).getTime() <= now) return <span className="muted">만료됨</span>;
            const d = daysUntil(t.expires_at);
            return <span className={d <= 14 ? "due due-soon" : undefined} title={fmtDate(t.expires_at)}>{fmtDate(t.expires_at)}{d <= 14 && ` (D-${d})`}</span>;
          } },
          { key: "act", header: <span className="sr-only">폐기</span>, width: 80, align: "right", render: (t) => (!t.revoked_at && (
            <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === t.id}
              onClick={() => confirm(`"${t.name}" 토큰을 폐기할까요? 이 토큰을 쓰는 CI는 바로 실패합니다.`) && revoke.mutate(t.id)}>폐기</Button>)) },
        ]} />
      <TokenDialog open={creating} onClose={() => setCreating(false)} projectKey={project.key} />
    </Section>
  );
}

// What the server's MCP tools do (mcp.go), one line each for the person setting up an agent.
const MCP_TOOLS: [string, string][] = [
  ["project_summary", "프로젝트 요약: 심각도별 열린 결과 수, 대상 수, 마지막 스캔 시각, 정책 기준"],
  ["list_findings", "결과 목록. 심각도·상태·종류·대상·검색어·조치 버전 유무로 거릅니다"],
  ["get_finding", "결과 한 건의 상세: 위치, 설치·조치 버전, 예외 상태"],
  ["get_vulnerability", "취약점(CVE) 설명, CVSS, 참고 링크와 이 프로젝트에서 영향받는 대상"],
  ["list_targets", "대상 목록: 종류, 마지막 스캔 시각, 심각도별 열린 결과 수"],
  ["list_scans", "최근 스캔: 상태, 결과 수, 정책 통과·실패와 그 이유"],
  ["get_scan", "스캔 한 건과 직전 스캔 대비 새 결과·해결·그대로인 결과 수"],
  ["list_exceptions", "예외 목록: 범위, 처리 방식, 상태, 요청자, 만료일"],
  ["search_packages", "패키지 찾기: 이름과 버전 조건으로 대상별 최신 패키지 목록에서 찾고, 패키지별 열린 취약점 수를 알려 줍니다"],
];

function Mcp({ project, owner }: { project: Project; owner: boolean }) {
  const toast = useToast();
  const url = `${location.origin}/mcp`;
  const config = JSON.stringify({ mcpServers: { [`jasca-${project.key}`]: { type: "http", url, headers: { Authorization: "Bearer <토큰>" } } } }, null, 2);
  const copy = async (text: string, what: string) => toast((await copyText(text)) ? `${what} 복사했습니다.` : "복사하지 못했습니다. 직접 선택해 복사하세요.", "info");
  return (
    <Section id="mcp" title="MCP 연동" meta="AI 에이전트가 이 프로젝트를 조회하는 주소">
      <div className="ci">
        <p className="mcp-lead">
          AI 코딩·보안 에이전트를 MCP(Model Context Protocol)로 연결하면 에이전트가 이 프로젝트의 결과, 대상, 스캔, 예외, 패키지 목록을 직접 조회합니다.
          조회만 할 수 있으며, <b>읽기</b> 권한이 있는 {owner ? <a href="#tokens">API 토큰</a> : "API 토큰"}이 필요합니다{!owner && "(프로젝트 소유자가 만듭니다)"}.
        </p>
        <div className="secret-box">
          <code className="mono">{url}</code>
          <Button size="sm" icon="copy" onClick={() => copy(url, "주소를")}>주소 복사</Button>
        </div>
        <div className="ci-code">
          <pre aria-label="MCP 클라이언트 설정"><code>{config}</code></pre>
          <Button size="sm" icon="copy" className="ci-copy" onClick={() => copy(config, "설정을")}>복사</Button>
        </div>
        <ul className="ci-notes">
          <li>Streamable HTTP(<code>type: "http"</code>)를 지원하는 MCP 클라이언트의 설정 파일에 넣고, <code>&lt;토큰&gt;</code>을 토큰 값으로 바꾸세요.</li>
          <li>토큰이 속한 프로젝트만 보입니다. 다른 프로젝트는 그 프로젝트의 토큰으로 따로 연결하세요.</li>
        </ul>
      </div>
      <Table<[string, string]> caption="MCP 도구" rows={MCP_TOOLS} rowKey={(t) => t[0]} dense
        columns={[
          { key: "name", header: "도구", width: 190, mono: true, render: (t) => t[0] },
          { key: "desc", header: "에이전트가 할 수 있는 일", render: (t) => t[1] },
        ]} />
    </Section>
  );
}

/** The policy sentence and its options: a project's policy and the admin default policy are written the same way. */
/** What is wrong with the count as typed, "" when it can be saved (the API takes whole numbers from 0 to 1,000,000). */
export const policyCountError = (p: Policy) => (Number.isInteger(p.max_count) && p.max_count >= 0 && p.max_count <= 1_000_000 ? "" : "허용 개수는 0부터 1,000,000까지의 정수로 입력하세요.");

export function PolicyFields({ p, set, disabled, label }: { p: Policy; set: (patch: Partial<Policy>) => void; disabled?: boolean; label: string }) {
  const off = disabled || !p.enabled;
  const countErr = policyCountError(p);
  return (
    <>
      <label className="check-row"><input type="checkbox" checked={p.enabled} disabled={disabled} onChange={(e) => set({ enabled: e.target.checked })} />{label}</label>
      <fieldset className="policy-rule" disabled={off}>
        <legend className="sr-only">실패 조건</legend>
        <span>열린 결과 중 심각도</span>
        <select className="input input-sm" aria-label="최소 심각도" value={p.min_severity} onChange={(e) => set({ min_severity: e.target.value as Severity })}>
          {SEVERITIES.filter((s) => s !== "UNKNOWN").map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
        </select>
        <span>이상이</span>
        {/* NaN (an emptied or half-typed box) shows as empty and is reported below instead of turning into 0 */}
        <input className="input input-sm num" type="number" min={0} max={1_000_000} step={1} aria-label="허용 개수" aria-invalid={countErr ? true : undefined} aria-describedby={countErr ? "policy-count-err" : undefined}
          value={Number.isNaN(p.max_count) ? "" : p.max_count} onChange={(e) => set({ max_count: e.target.value === "" ? NaN : Number(e.target.value) })} />
        <span>개를 넘으면 정책 실패</span>
      </fieldset>
      {countErr && <p id="policy-count-err" className="field-err" role="alert">{countErr}</p>}
      <div className="policy-opts">
        <label className="check-row"><input type="checkbox" checked={p.new_only} disabled={off} onChange={(e) => set({ new_only: e.target.checked })} />이번 스캔에서 새로 나온 결과만 셉니다</label>
        <label className="check-row"><input type="checkbox" checked={p.fixable_only} disabled={off} onChange={(e) => set({ fixable_only: e.target.checked })} />조치 버전이 있는 결과만 셉니다</label>
      </div>
      <p className="side-note">승인된 예외(위험 수용·오탐)는 세지 않습니다. 판정 중 오류가 나면 정책 실패로 처리합니다.</p>
    </>
  );
}

function PolicyForm({ project, owner }: { project: Project; owner: boolean }) {
  const path = `/projects/${project.key}/policy`;
  const q = useApi<Policy>(path);
  const [p, setP] = useState<Policy | null>(null);
  useEffect(() => { if (q.data) setP(q.data); }, [q.data]);
  const save = useSave(() => api.put(path, p!), "정책을 저장했습니다.", [path]);
  if (!p) return <Section id="policy" title="정책"><span className="skeleton skeleton-block" style={{ height: 120 }} /></Section>;
  const dirty = JSON.stringify(p) !== JSON.stringify(q.data);
  const set = (patch: Partial<Policy>) => setP({ ...p, ...patch });
  return (
    <Section id="policy" title="정책" meta="스캔할 때마다 정책 통과·정책 실패를 정합니다">
      <form className="form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
        <PolicyFields p={p} set={set} disabled={!owner} label="정책 사용 (끄면 스캔을 판정하지 않음 · CI에는 통과로 응답)" />
        {owner && <div className="form-actions"><Button type="submit" variant="primary" disabled={!dirty || !!policyCountError(p)} loading={save.isPending}>저장</Button></div>}
      </form>
    </Section>
  );
}

function Notify({ project, owner }: { project: Project; owner: boolean }) {
  const path = `/projects/${project.key}/notify`;
  const channels = useApi<Channel[] | null>("/channels");
  const subs = useApi<NotifySub[] | null>(path);
  const [draft, setDraft] = useState<Record<number, string[]> | null>(null);
  useEffect(() => setDraft(null), [subs.data]);
  const current: Record<number, string[]> = draft ?? Object.fromEntries((subs.data ?? []).map((s) => [s.channel_id, s.events]));
  const save = useSave(() => api.put(path, Object.entries(current).filter(([, ev]) => ev.length).map(([id, events]) => ({ channel_id: Number(id), events }))),
    "알림 구독을 저장했습니다.", [path]);
  const toggle = (ch: number, ev: string) => {
    const cur = current[ch] ?? [];
    setDraft({ ...current, [ch]: cur.includes(ev) ? cur.filter((x) => x !== ev) : [...cur, ev] });
  };
  const list = channels.data ?? [];
  return (
    <Section id="notify" title="알림" meta="채널은 관리자가 등록합니다. 프로젝트마다 받을 이벤트를 고릅니다."
      actions={owner && draft && (
        <>
          <Button size="sm" variant="ghost" onClick={() => setDraft(null)}>되돌리기</Button>
          <Button size="sm" variant="primary" loading={save.isPending} onClick={() => save.mutate(undefined)}>변경 저장</Button>
        </>
      )}>
      {channels.isError ? (channels.error.status === 404
          ? <Empty compact icon="megaphone" title="알림 채널 목록을 쓸 수 없습니다" description="이 서버 버전에는 알림 기능이 아직 없습니다." />
          : <div className="alert alert-danger" role="alert"><Icon name="alert" />{channels.error.message}</div>)
        : channels.isPending || subs.isPending ? <span className="skeleton skeleton-block" style={{ height: 80 }} />
        : !list.length ? <Empty compact icon="megaphone" title="등록된 알림 채널이 없습니다" description="관리자에게 Mattermost나 이메일 채널 등록을 요청하세요." />
        : (
          <div className="notify-grid">
            {list.map((c) => (
              <fieldset key={c.id} className="notify-ch" disabled={!owner}>
                <legend><b>{c.name}</b><span className="tag tag-quiet">{c.kind === "email" ? "이메일" : "Mattermost"}</span>
                  {(current[c.id] ?? []).length > 0 ? <span className="muted">{current[c.id].length}개 이벤트</span> : <span className="muted">받지 않음</span>}</legend>
                <div className="notify-events">
                  {NOTIFY_EVENTS.map(([ev, label]) => (
                    <label key={ev} className="check-row"><input type="checkbox" checked={(current[c.id] ?? []).includes(ev)} onChange={() => toggle(c.id, ev)} />{label}</label>
                  ))}
                </div>
              </fieldset>
            ))}
          </div>
        )}
    </Section>
  );
}

function Danger({ project }: { project: Project }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const del = useMutation<unknown, ApiError>({
    mutationFn: () => api.del(`/projects/${project.key}`),
    onSuccess: () => {
      qc.removeQueries({ predicate: (q) => String(q.queryKey[0]).startsWith(`/projects/${project.key}`) });
      qc.invalidateQueries({ queryKey: ["/projects"] });
      toast(`프로젝트 "${project.name}"을(를) 삭제했습니다.`, "ok");
      navigate("/projects");
    },
  });
  const close = () => { setOpen(false); setTyped(""); del.reset(); };
  return (
    <Section id="danger" title="프로젝트 삭제" tone="danger">
      <div className="danger-row">
        <p>대상, 스캔, 결과, 예외, 토큰이 모두 지워지며 되돌릴 수 없습니다. 감사 로그는 남습니다.</p>
        <Button variant="danger" onClick={() => setOpen(true)}>프로젝트 삭제</Button>
      </div>
      <Dialog open={open} onClose={close} size="sm" title="프로젝트를 삭제할까요?" description={`"${project.name}"의 모든 데이터가 지워집니다.`}
        footer={<><Button onClick={close}>취소</Button><Button variant="danger" disabled={typed !== project.key} loading={del.isPending} onClick={() => del.mutate()}>영구 삭제</Button></>}>
        <Field label={<>확인을 위해 키 <span className="mono">{project.key}</span>를 입력하세요</>}>
          <input className="input mono" value={typed} autoComplete="off" spellCheck={false} onChange={(e) => setTyped(e.target.value)} />
        </Field>
        {del.isError && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" />{del.error.message}</div>}
      </Dialog>
    </Section>
  );
}
