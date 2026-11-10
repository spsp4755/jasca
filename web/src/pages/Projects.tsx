import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type ApiError } from "../api/client";
import { useApi } from "../api/hooks";
import type { Project, ProjectCreate } from "../api/types";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Empty from "../components/Empty";
import Field from "../components/Field";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import Table, { type Column } from "../components/Table";
import { useToast } from "../components/Toast";
import { ROLE_LABEL, fmtDateTime, fmtNumber, fmtRelative } from "../lib/format";
import { SummaryCell } from "./Home";

export const KEY_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
/** "Payment API v2" → "payment-api-v2"; Hangul and other letters are dropped, so a Korean name suggests nothing. */
export const suggestKey = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40).replace(/-+$/, "");

/** Name, open count, counts by severity and last scan: the cells the project list and the report list share. `to` is where the name leads. */
export function projectColumns(to: (p: Project) => string): Column<Project>[] {
  return [
    { key: "name", header: "프로젝트", render: (p) => (
      <span className="proj-cell">
        <Link to={to(p)} className="proj-name">{p.name}</Link>
        <span className="proj-sub"><span className="mono">{p.key}</span>{p.description && <> · {p.description}</>}</span>
      </span>) },
    { key: "open", header: "열린 결과", width: 90, align: "right", render: (p) => <b className={`num${p.counts.open ? "" : " muted"}`}>{fmtNumber(p.counts.open)}</b> },
    { key: "sev", header: "심각도별", width: 280, render: (p) => <SummaryCell s={p.counts} /> },
    { key: "scan", header: "마지막 스캔", width: 120, align: "right", render: (p) => (p.last_scan_at
      ? <span className="muted" title={fmtDateTime(p.last_scan_at)}>{fmtRelative(p.last_scan_at)}</span>
      : <span className="muted">없음</span>) },
  ];
}

export default function Projects() {
  const q = useApi<Project[]>("/projects");
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState("");
  const all = q.data ?? [];
  const f = filter.trim().toLowerCase();
  const rows = f ? all.filter((p) => `${p.key} ${p.name} ${p.description}`.toLowerCase().includes(f)) : all;
  const [name, ...counts] = projectColumns((p) => `/projects/${p.key}`);
  return (
    <>
      <PageHeader title="프로젝트" description="내가 멤버이거나 볼 수 있는 프로젝트입니다. 숫자는 열린 결과입니다."
        actions={<Button variant="primary" icon="folder" onClick={() => setCreating(true)}>새 프로젝트</Button>} />
      {q.isError && <div className="alert alert-danger" role="alert"><Icon name="alert" />{q.error.message}<Button size="sm" className="alert-action" onClick={() => q.refetch()}>다시 시도</Button></div>}
      {all.length > 8 && (
        <div className="list-filter">
          <Icon name="search" />
          <input className="input" type="search" aria-label="프로젝트 찾기" placeholder="이름이나 키로 찾기" value={filter} onChange={(e) => setFilter(e.target.value)} />
          {f && <span className="muted">{rows.length}개</span>}
        </div>
      )}
      <div className="panel">
        <Table<Project> caption="프로젝트 목록" rows={rows} rowKey={(p) => p.key} loading={q.isPending} onRowClick={(p) => navigate(`/projects/${p.key}`)}
          empty={f ? <Empty compact icon="search" title="찾는 프로젝트가 없습니다" />
            : <Empty icon="folder" title="아직 프로젝트가 없습니다" description="프로젝트를 만들면 CI 업로드용 토큰과 명령을 바로 받을 수 있습니다. 만든 사람이 소유자가 됩니다."
                action={<Button variant="primary" onClick={() => setCreating(true)}>새 프로젝트</Button>} />}
          columns={[
            name,
            { key: "role", header: "내 역할", width: 96, render: (p) => (p.my_role ? <span className={`tag${p.my_role === "owner" ? "" : " tag-quiet"}`}>{ROLE_LABEL[p.my_role]}</span> : null) },
            ...counts,
          ]} />
      </div>
      <NewProjectDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

function NewProjectDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [keyEdited, setKeyEdited] = useState(false);
  const [desc, setDesc] = useState("");
  const [tried, setTried] = useState(false);
  const create = useMutation<Project, ApiError, ProjectCreate>({
    mutationFn: (b) => api.post<Project>("/projects", b),
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: ["/projects"] });
      toast(`프로젝트 "${p.name}"을(를) 만들었습니다.`, "ok");
      close();
      navigate(`/projects/${p.key}`);
    },
  });
  const close = () => { onClose(); setName(""); setKey(""); setKeyEdited(false); setDesc(""); setTried(false); create.reset(); };
  const nameErr = !name.trim() ? "이름을 입력하세요." : name.trim().length > 100 ? "이름은 100자 이하로 입력하세요." : "";
  const keyErr = !key ? "키를 입력하세요." : !KEY_RE.test(key)
    ? "영문 소문자, 숫자, 하이픈(-)으로 2~40자. 첫 글자는 영문 소문자나 숫자여야 합니다." : "";
  const descErr = desc.length > 2000 ? "설명은 2000자 이하로 입력하세요." : "";
  const conflict = create.error?.status === 409;
  const submit = () => {
    setTried(true);
    if (nameErr || keyErr || descErr) return;
    create.mutate({ key, name: name.trim(), description: desc.trim() });
  };
  return (
    <Dialog open={open} onClose={close} title="새 프로젝트" description="만든 사람이 소유자가 되며, 멤버와 토큰은 만든 뒤 설정에서 추가합니다."
      footer={<><Button onClick={close}>취소</Button><Button variant="primary" loading={create.isPending} onClick={submit}>만들기</Button></>}>
      <form onSubmit={(e) => { e.preventDefault(); submit(); }} style={{ display: "contents" }}>
        <Field label="이름" required error={tried ? nameErr : undefined}>
          <input className="input" value={name} autoFocus maxLength={120} placeholder="예: 결제 API"
            onChange={(e) => { setName(e.target.value); if (!keyEdited) setKey(suggestKey(e.target.value)); }} />
        </Field>
        <Field label="키" required error={conflict ? "이미 쓰는 키입니다. 다른 키를 입력하세요." : (tried || keyEdited) && key ? keyErr || undefined : tried ? keyErr : undefined}
          hint={`주소와 CI 명령에 들어가며 나중에 바꿀 수 없습니다.${!keyEdited && name && !key ? " 한글 이름이면 키를 직접 입력하세요." : ""}`}>
          <input className="input mono" value={key} maxLength={40} placeholder="예: payment-api" spellCheck={false}
            onChange={(e) => { setKey(e.target.value.toLowerCase()); setKeyEdited(true); if (conflict) create.reset(); }} />
        </Field>
        <Field label="설명" error={descErr || undefined}>
          <textarea className="input" rows={3} value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="어떤 서비스인지, 담당 팀 등" />
        </Field>
        {create.isError && !conflict && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" />{create.error.message}</div>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
