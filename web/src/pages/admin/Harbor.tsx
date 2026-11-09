import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import Dialog from "../../components/Dialog";
import Table from "../../components/Table";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { copyText } from "../../lib/clipboard";
import { fmtDateTime } from "../../lib/format";
import { useToast } from "../../components/Toast";
import type { HarborLink, HarborLinkCreated, HarborMapping, HarborUnmapped, Project } from "../../api/types";
import { Loading, Panel, SecretField, useSave } from "./parts";

type Form = { id?: number; name: string; base_url: string; robot_user: string; robot_secret: string; secretSet: boolean };
const EMPTY: Form = { name: "", base_url: "", robot_user: "", robot_secret: "", secretSet: false };

function Once({ label, value }: { label: string; value: string }) {
  const toast = useToast();
  return (
    <Field label={label}>
      <div style={{ display: "flex", gap: 6 }}>
        <input className="input mono" readOnly value={value} onFocus={(e) => e.currentTarget.select()} />
        <Button icon="copy" aria-label={`${label} 복사`} onClick={async () => toast((await copyText(value)) ? "복사했습니다." : "복사하지 못했습니다. 직접 선택해 복사하세요.", "info")} />
      </div>
    </Field>
  );
}

function Mappings({ link, projects, onClose }: { link: HarborLink; projects: Project[]; onClose: () => void }) {
  const q = useApi<HarborMapping[]>(`/admin/harbor/${link.id}/mappings`);
  const [rows, setRows] = useState<HarborMapping[]>([]);
  useEffect(() => { if (q.data) setRows(q.data); }, [q.data]);
  const save = useSave(() => api.put(`/admin/harbor/${link.id}/mappings`, rows), { ok: "매핑을 저장했습니다.", invalidate: [`/admin/harbor/${link.id}/mappings`], onDone: onClose });
  const upd = (i: number, p: Partial<HarborMapping>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const valid = rows.every((r) => r.harbor_project.trim() && r.project_id);
  return (
    <Dialog open onClose={onClose} size="lg" title={`매핑 · ${link.name}`}
      description="Harbor 프로젝트와 저장소 패턴(예: web/*, * = 전체)을 JASCA 프로젝트에 연결합니다. 패턴이 더 구체적인 행이 먼저 적용됩니다."
      footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={!valid} loading={save.isPending} onClick={() => save.mutate(undefined)}>저장</Button></>}>
      <Loading q={q} />
      {rows.map((r, i) => (
        <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1.3fr auto", gap: 8 }}>
          <input className="input" aria-label="Harbor 프로젝트" placeholder="Harbor 프로젝트" value={r.harbor_project} onChange={(e) => upd(i, { harbor_project: e.target.value })} />
          <input className="input mono" aria-label="저장소 패턴" placeholder="*" value={r.repo_pattern} onChange={(e) => upd(i, { repo_pattern: e.target.value })} />
          <select className="input" aria-label="JASCA 프로젝트" value={r.project_id || ""} onChange={(e) => upd(i, { project_id: Number(e.target.value) })}>
            <option value="">프로젝트 선택</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.key})</option>)}
          </select>
          <Button variant="ghost" icon="x" aria-label="행 삭제" onClick={() => setRows(rows.filter((_, j) => j !== i))} />
        </div>
      ))}
      <div><Button size="sm" icon="check" onClick={() => setRows([...rows, { harbor_project: "", repo_pattern: "*", project_id: 0 }])}>행 추가</Button></div>
    </Dialog>
  );
}

export default function Harbor() {
  const links = useApi<HarborLink[]>("/admin/harbor");
  const unmapped = useApi<HarborUnmapped[]>("/admin/harbor/unmapped");
  const projects = useApi<Project[]>("/projects");
  const toast = useToast();
  const [form, setForm] = useState<Form | null>(null);
  const [created, setCreated] = useState<HarborLinkCreated | null>(null);
  const [map, setMap] = useState<HarborLink | null>(null);
  const [pick, setPick] = useState<Record<number, string>>({});
  const body = (f: Form) => ({ name: f.name, base_url: f.base_url, robot_user: f.robot_user, ...(f.robot_secret ? { robot_secret: f.robot_secret } : {}) });
  const saveLink = useSave<Form, HarborLinkCreated | void>((f: Form) => (f.id ? api.put<void>(`/admin/harbor/${f.id}`, body(f)) : api.post<HarborLinkCreated>("/admin/harbor", body(f))), {
    invalidate: ["/admin/harbor"], onDone: (r) => { if (r) setCreated(r as HarborLinkCreated); else toast("저장했습니다.", "ok"); setForm(null); },
  });
  const del = useSave((id: number) => api.del(`/admin/harbor/${id}`), { ok: "삭제했습니다.", invalidate: ["/admin/harbor", "/admin/harbor/unmapped"] });
  const test = useSave((id: number) => api.post<{ error?: string }>(`/admin/harbor/${id}/test`), { onDone: (r) => (r?.error ? toast(`연결 실패: ${r.error}`, "error") : toast("Harbor에 연결했습니다.", "ok")) });
  const assign = useSave(({ id, project_id }: { id: number; project_id: number }) => api.post(`/admin/harbor/unmapped/${id}/assign`, { project_id }), { ok: "프로젝트에 연결했습니다.", invalidate: ["/admin/harbor/unmapped"] });
  const set = (k: keyof Form) => (e: { target: { value: string } }) => setForm({ ...form!, [k]: e.target.value });
  const ready = form && form.name.trim() && form.base_url.trim() && form.robot_user.trim() && (form.id || form.robot_secret);
  return (
    <>
      <PageHeader title="Harbor" description="Harbor에 이미지가 올라오면 웹훅으로 알림을 받아 Trivy로 검사합니다."
        actions={<Button variant="primary" icon="check" onClick={() => setForm(EMPTY)}>Harbor 연결 추가</Button>} />
      <Panel title="연결">
        <Loading q={links} />
        <Table<HarborLink> dense rowKey={(l) => l.id} rows={links.data ?? []} loading={links.isLoading} caption="Harbor 연결" empty={<span className="muted">연결된 Harbor가 없습니다. 위의 &quot;Harbor 연결 추가&quot;로 시작하세요.</span>}
          columns={[
            { key: "name", header: "이름", render: (l) => <b>{l.name}</b> },
            { key: "url", header: "주소", render: (l) => <span className="mono">{l.base_url}</span> },
            { key: "robot", header: "로봇 계정", render: (l) => l.robot_user },
            { key: "act", header: "", align: "right", nowrap: true, render: (l) => (
              <div className="admin-actions" style={{ justifyContent: "flex-end" }}>
                <Button size="sm" loading={test.isPending && test.variables === l.id} onClick={() => test.mutate(l.id)}>연결 시험</Button>
                <Button size="sm" onClick={() => setMap(l)}>매핑</Button>
                <Button size="sm" onClick={() => setForm({ id: l.id, name: l.name, base_url: l.base_url, robot_user: l.robot_user, robot_secret: "", secretSet: l.robot_secret_set })}>수정</Button>
                <Button size="sm" variant="danger" onClick={() => confirm(`"${l.name}" 연결을 삭제할까요? 매핑도 함께 지워집니다.`) && del.mutate(l.id)}>삭제</Button>
              </div>) },
          ]} />
      </Panel>
      <Panel title="매핑되지 않은 이미지" meta={`${unmapped.data?.length ?? 0}건`}>
        <p className="muted">웹훅으로 받았지만 어느 프로젝트에도 매핑되지 않은 이미지입니다. 프로젝트를 고르면 연결하고 검사합니다.</p>
        <Table<HarborUnmapped> dense rowKey={(u) => u.id} rows={unmapped.data ?? []} loading={unmapped.isLoading} caption="매핑되지 않은 이미지" empty={<span className="muted">매핑되지 않은 이미지가 없습니다.</span>}
          columns={[
            { key: "repo", header: "저장소", render: (u) => <span className="mono">{u.repository}{u.tag && `:${u.tag}`}</span> },
            { key: "link", header: "Harbor", render: (u) => links.data?.find((l) => l.id === u.link_id)?.name ?? u.link_id },
            { key: "at", header: "받은 시각", nowrap: true, render: (u) => fmtDateTime(u.received_at) },
            { key: "assign", header: "프로젝트에 연결", nowrap: true, render: (u) => (
              <div className="admin-actions">
                <select className="input" aria-label="프로젝트" value={pick[u.id] ?? ""} onChange={(e) => setPick({ ...pick, [u.id]: e.target.value })}>
                  <option value="">프로젝트 선택</option>{(projects.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name} ({p.key})</option>)}
                </select>
                <Button size="sm" variant="primary" disabled={!pick[u.id]} onClick={() => assign.mutate({ id: u.id, project_id: Number(pick[u.id]) })}>연결</Button>
              </div>) },
          ]} />
      </Panel>

      <Dialog open={!!form} onClose={() => setForm(null)} title={form?.id ? "Harbor 연결 수정" : "Harbor 연결 추가"}
        footer={<><Button onClick={() => setForm(null)}>취소</Button><Button variant="primary" disabled={!ready} loading={saveLink.isPending} onClick={() => saveLink.mutate(form!)}>저장</Button></>}>
        {form && <>
          <Field label="이름" required><input className="input" value={form.name} onChange={set("name")} /></Field>
          <Field label="Harbor 주소" hint="예: https://harbor.example.com" required><input className="input" value={form.base_url} onChange={set("base_url")} /></Field>
          <Field label="로봇 계정" hint="이미지를 읽을 수 있는 robot account 이름. 예: robot$jasca" required><input className="input" value={form.robot_user} onChange={set("robot_user")} /></Field>
          <SecretField label="로봇 계정 Secret" isSet={form.secretSet} value={form.robot_secret} onChange={(v) => setForm({ ...form, robot_secret: v })} />
        </>}
      </Dialog>

      <Dialog open={!!created} onClose={() => setCreated(null)} title="웹훅 설정" size="md"
        description="이 비밀값은 지금 한 번만 보입니다. 닫기 전에 Harbor 웹훅에 입력하세요."
        footer={<Button variant="primary" onClick={() => setCreated(null)}>닫기</Button>}>
        {created && <>
          <Once label="웹훅 URL" value={created.webhook_url} />
          <Once label="웹훅 Secret (Authorization 헤더 값)" value={created.webhook_secret} />
          <p className="muted">Harbor 프로젝트 → Webhooks에서 이벤트 &quot;Scanning finished/Artifact pushed&quot;를 고르고, Auth Header에 위 Secret을 넣습니다.</p>
        </>}
      </Dialog>
      {map && <Mappings link={map} projects={projects.data ?? []} onClose={() => setMap(null)} />}
    </>
  );
}
