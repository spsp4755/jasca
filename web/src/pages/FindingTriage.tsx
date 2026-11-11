import { useMutation, useQueries, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect, useId, useState } from "react";
import { ApiError, api, qs } from "../api/client";
import { useMe } from "../api/hooks";
import type { Assignee, Finding, Me, ProjectRole } from "../api/types";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Icon from "../components/Icon";
import { useToast } from "../components/Toast";
import { SEVERITY_LABEL, dateOf, fmtDate, fmtDateTime, fmtDue } from "../lib/format";
import "../styles/due.css";

// Who fixes a finding and by when: the cells, the picker, the drawer block and the bulk dialog.

/** Who may assign a finding or set its deadline, as PATCH /findings/{id} decides it: a member or owner of its project, or a security user. */
export const canTriage = (role: ProjectRole | "" | undefined, security: boolean) => role === "member" || role === "owner" || security;

const asAssignee = (me: Me): Assignee => ({ id: me.id, name: me.name || me.username, username: me.username, active: true });

/** Everything that shows an assignee, a deadline or a count of them. */
export const refreshTriage = (qc: QueryClient) => qc.invalidateQueries({ predicate: (q) => /^\/(findings|dashboard|projects)/.test(String(q.queryKey[0])) });

/** A deadline as people say it ("3일 남음"), the exact time in the title. Overdue is the danger colour plus an icon and the word 지남. */
export function DueText({ at }: { at: string | null }) {
  if (!at) return <span className="muted">—</span>;
  const d = fmtDue(at);
  return (
    <span className={`deadline${d.over ? " deadline-over" : d.days <= 3 ? " deadline-soon" : ""}`} title={`기한 ${fmtDateTime(at)}`}>
      {d.over && <Icon name="alert" size={13} />}{d.text}
    </span>
  );
}

export function AssigneeName({ a }: { a: Assignee | null }) {
  if (!a) return <span className="muted">—</span>;
  return <span className="assignee" title={`${a.name} (${a.username})${a.active ? "" : " · 비활성 계정"}`}><span className="assignee-name">{a.name}</span>{!a.active && <span className="tag tag-quiet">비활성</span>}</span>;
}

/** Combobox over GET /projects/{key}/assignees?q=: the active users who can see every one of `projects`. */
export function AssigneePicker({ projects, onPick }: { projects: string[]; onPick: (a: Assignee) => void }) {
  const id = useId();
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  useEffect(() => { const t = setTimeout(() => setQ(text.trim()), 220); return () => clearTimeout(t); }, [text]);
  // shortcut: each project answers its first 20 matches, so across several projects a common user can be missing
  // until the search narrows; ask the server for the intersection if selections ever span many projects.
  const res = useQueries({
    queries: projects.map((k) => {
      const path = `/projects/${encodeURIComponent(k)}/assignees${qs({ q })}`;
      return { queryKey: [path], queryFn: ({ signal }: { signal: AbortSignal }) => api.get<Assignee[]>(path, { signal }), enabled: open, staleTime: 60_000 };
    }),
  });
  const lists = res.map((r) => r.data ?? []);
  const items = (lists[0] ?? []).filter((a) => lists.every((l) => l.some((b) => b.id === a.id)));
  const failed = res.find((r) => r.isError)?.error as ApiError | undefined;
  const pick = (a: Assignee) => { onPick(a); setText(""); setQ(""); setActive(0); setOpen(false); };
  return (
    <div className="picker assignee-picker">
      <label htmlFor={`${id}-i`} className="sr-only">담당자 찾기</label>
      <input id={`${id}-i`} className="input input-sm" role="combobox" aria-expanded={open} aria-controls={`${id}-l`} aria-autocomplete="list"
        aria-activedescendant={open && items[active] ? `${id}-o${active}` : undefined}
        placeholder="이름이나 아이디로 찾기" value={text} autoComplete="off"
        onChange={(e) => { setText(e.target.value); setOpen(true); setActive(0); }}
        onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 120)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, items.length - 1)); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
          else if (e.key === "Enter" && open && items[active]) { e.preventDefault(); pick(items[active]); }
          else if (e.key === "Escape" && open) { e.stopPropagation(); e.preventDefault(); setOpen(false); }
        }} />
      {open && (
        <ul id={`${id}-l`} role="listbox" className="picker-list" aria-label="지정할 수 있는 사용자">
          {failed ? <li className="picker-note">{failed.message}</li>
            : res.some((r) => r.isPending) ? <li className="picker-note">찾는 중…</li>
            : !items.length ? <li className="picker-note">{q ? "일치하는 사용자가 없습니다." : "지정할 수 있는 사용자가 없습니다."} 이 프로젝트를 볼 수 있는 활성 사용자만 나옵니다.</li>
            : items.map((a, i) => (
              <li key={a.id} id={`${id}-o${i}`} role="option" aria-selected={i === active}
                className="picker-opt" onMouseDown={(e) => e.preventDefault()} onMouseEnter={() => setActive(i)} onClick={() => pick(a)}>
                <span>{a.name}</span>{a.name !== a.username && <span className="mono muted">{a.username}</span>}
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}

/** The drawer's 담당자 · 기한 block. Read-only unless `canEdit`; only an open finding has a deadline to set. */
export function Triage({ f, canEdit }: { f: Finding; canEdit: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const me = useMe().data;
  const [date, setDate] = useState("");
  useEffect(() => setDate(""), [f.id, f.due_at]);
  const save = useMutation<Finding, ApiError, { assignee_id?: number | null; due_at?: string | null }>({
    mutationFn: (b) => api.patch<Finding>(`/findings/${f.id}`, b),
    onSuccess: (r) => { qc.setQueryData([`/findings/${f.id}`], r); void refreshTriage(qc); },
    onError: (e) => toast(e.message, "error"),
  });
  const open = f.status === "open";
  const current = f.due_at ? dateOf(f.due_at) : "";
  const policy = f.sla_days ? `정책: ${SEVERITY_LABEL[f.severity]} ${f.sla_days}일` : ""; // where the date comes from
  return (
    <section className="triage" aria-label="담당자와 기한">
      <div className="triage-row">
        <span className="triage-label">담당자</span>
        <div className="triage-val">
          {f.assignee ? <AssigneeName a={f.assignee} /> : <span className="muted">미지정</span>}
          {canEdit && (
            <span className="triage-edit">
              {me && f.assignee?.id !== me.id && <Button size="sm" disabled={save.isPending} onClick={() => save.mutate({ assignee_id: me.id })}>나에게</Button>}
              {f.assignee && <Button size="sm" variant="ghost" disabled={save.isPending} onClick={() => save.mutate({ assignee_id: null })}>지정 해제</Button>}
              <AssigneePicker projects={[f.project_key]} onPick={(a) => save.mutate({ assignee_id: a.id })} />
            </span>
          )}
        </div>
      </div>
      <div className="triage-row">
        <span className="triage-label">기한</span>
        <div className="triage-val">
          {!open ? <span className="muted">없음 · 열린 결과에만 기한이 있습니다</span>
            : f.due_at ? <><DueText at={f.due_at} /><span className="num">{fmtDate(f.due_at)}</span><span className="muted">{f.due_manual ? `직접 정함${policy && ` · ${policy}`}` : policy}</span></>
            : <span className="muted">없음 · 정책에 {SEVERITY_LABEL[f.severity]} 기한이 없습니다</span>}
          {canEdit && open && (
            <span className="triage-edit">
              <input className="input input-sm" type="date" aria-label="기한 날짜" value={date || current} disabled={save.isPending} onChange={(e) => setDate(e.target.value)} />
              <Button size="sm" disabled={!date || date === current} loading={save.isPending && !!date} onClick={() => save.mutate({ due_at: date })}>기한 저장</Button>
              {f.due_manual && <Button size="sm" variant="ghost" disabled={save.isPending} onClick={() => save.mutate({ due_at: null })}>정책 기한으로 되돌리기</Button>}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}

/** Gives the chosen findings to one person, or to nobody. POST /findings/assign is all or nothing and takes 500 at a time. */
export function AssignDialog({ open, findings, onClose, onDone }: { open: boolean; findings: Finding[]; onClose: () => void; onDone?: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const me = useMe().data;
  const [pick, setPick] = useState<Assignee | null>(null);
  const projects = [...new Set(findings.map((f) => f.project_key))];
  const close = () => { onClose(); setPick(null); send.reset(); };
  const send = useMutation<void, ApiError, Assignee | null>({
    mutationFn: async (to) => {
      const ids = findings.map((f) => f.id);
      for (let i = 0; i < ids.length; i += 500) await api.post("/findings/assign", { ids: ids.slice(i, i + 500), assignee_id: to?.id ?? null });
    },
    onSuccess: (_, to) => {
      toast(to ? `${findings.length}건을 ${to.name} 님에게 지정했습니다.` : `${findings.length}건의 담당자 지정을 해제했습니다.`, "ok");
      close(); onDone?.();
    },
    onSettled: () => refreshTriage(qc), // a later chunk may have failed after an earlier one was saved
  });
  const assigned = findings.filter((f) => f.assignee).length;
  return (
    <Dialog open={open} onClose={close} title="담당자 지정"
      description={`고른 결과 ${findings.length}건${projects.length > 1 ? ` (프로젝트 ${projects.length}개)` : ""}을 한 사람에게 맡깁니다.${assigned ? ` 이미 담당자가 있는 ${assigned}건은 새 담당자로 바뀝니다.` : ""}`}
      footer={(
        <>
          <Button onClick={close}>취소</Button>
          {assigned > 0 && <Button disabled={send.isPending} onClick={() => send.mutate(null)}>지정 해제</Button>}
          <Button variant="primary" disabled={!pick} loading={send.isPending} onClick={() => send.mutate(pick)}>{pick ? `${pick.name} 님에게 지정` : "지정"}</Button>
        </>
      )}>
      <div className="assign-pick">
        <AssigneePicker projects={projects} onPick={setPick} />
        {me && <Button size="sm" onClick={() => setPick(asAssignee(me))}>나에게</Button>}
      </div>
      <p className="field-hint" style={{ margin: 0 }}>{projects.length > 1 ? "고른 결과의 프로젝트를 모두 볼 수 있는 활성 사용자만 지정할 수 있습니다." : "이 프로젝트를 볼 수 있는 활성 사용자만 지정할 수 있습니다."}</p>
      {pick && <p className="assign-chosen" role="status"><Icon name="check" size={15} /><span><b>{pick.name}</b>{pick.name !== pick.username && <span className="mono muted"> {pick.username}</span>} 님에게 지정합니다.</span></p>}
      {send.isError && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" />{send.error.message}</div>}
    </Dialog>
  );
}
