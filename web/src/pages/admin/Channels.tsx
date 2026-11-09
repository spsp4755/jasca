import { useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import Dialog from "../../components/Dialog";
import Table from "../../components/Table";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { fmtDate } from "../../lib/format";
import { useToast } from "../../components/Toast";
import type { ChannelKind, NotifyChannel } from "../../api/types";
import { Check, Loading, Panel, SecretField, useSave } from "./parts";

const KIND: Record<ChannelKind, string> = { mattermost: "Mattermost", email: "이메일" };
type Form = { id?: number; kind: ChannelKind; name: string; enabled: boolean; webhook_url: string; webhookSet: boolean; to: string };
const EMPTY: Form = { kind: "mattermost", name: "", enabled: true, webhook_url: "", webhookSet: false, to: "" };

// Assumed config shapes: mattermost {webhook_url}, email {to: string[]}. The webhook URL is treated as a secret.
export default function Channels() {
  const q = useApi<NotifyChannel[]>("/admin/channels");
  const toast = useToast();
  const [f, setF] = useState<Form | null>(null);
  const cfg = (x: Form) => (x.kind === "mattermost"
    ? (x.webhook_url ? { webhook_url: x.webhook_url } : undefined)
    : { to: x.to.split(/[\s,;]+/).filter(Boolean) });
  const save = useSave((x: Form) => {
    const body = { kind: x.kind, name: x.name, enabled: x.enabled, config: cfg(x) };
    return x.id ? api.put(`/admin/channels/${x.id}`, body) : api.post("/admin/channels", body);
  }, { ok: "저장했습니다.", invalidate: ["/admin/channels", "/channels"], onDone: () => setF(null) });
  const del = useSave((id: number) => api.del(`/admin/channels/${id}`), { ok: "삭제했습니다.", invalidate: ["/admin/channels", "/channels"] });
  const test = useSave((id: number) => api.post<{ error?: string }>(`/admin/channels/${id}/test`), { onDone: (r) => (r?.error ? toast(`시험 발송 실패: ${r.error}`, "error") : toast("시험 메시지를 보냈습니다.", "ok")) });
  const edit = (c: NotifyChannel) => setF({
    id: c.id, kind: c.kind, name: c.name, enabled: c.enabled, webhook_url: "", webhookSet: c.kind === "mattermost",
    to: Array.isArray(c.config?.to) ? (c.config.to as string[]).join(", ") : "",
  });
  const ready = f && f.name.trim() && (f.kind === "email" ? f.to.trim() : f.webhook_url || f.webhookSet);
  return (
    <>
      <PageHeader title="알림 채널" description="새 취약점, 정책 실패 등을 보낼 곳입니다. 프로젝트 소유자가 프로젝트별로 이 채널과 받을 이벤트를 고릅니다."
        actions={<Button variant="primary" icon="check" onClick={() => setF(EMPTY)}>채널 추가</Button>} />
      <Panel title="채널">
        <Loading q={q} />
        <Table<NotifyChannel> dense rowKey={(c) => c.id} rows={q.data ?? []} loading={q.isLoading} caption="알림 채널" empty={<span className="muted">채널이 없습니다. &quot;채널 추가&quot;로 만드세요.</span>}
          columns={[
            { key: "name", header: "이름", render: (c) => <b>{c.name}</b> },
            { key: "kind", header: "종류", render: (c) => <span className="tag tag-quiet">{KIND[c.kind] ?? c.kind}</span> },
            { key: "on", header: "상태", render: (c) => (c.enabled ? "사용" : <span className="muted">중지</span>) },
            { key: "at", header: "만든 날", nowrap: true, render: (c) => fmtDate(c.created_at) },
            { key: "act", header: "", align: "right", nowrap: true, render: (c) => (
              <div className="admin-actions" style={{ justifyContent: "flex-end" }}>
                <Button size="sm" loading={test.isPending && test.variables === c.id} onClick={() => test.mutate(c.id)}>시험 발송</Button>
                <Button size="sm" onClick={() => edit(c)}>수정</Button>
                <Button size="sm" variant="danger" onClick={() => confirm(`"${c.name}" 채널을 삭제할까요? 프로젝트 알림 설정에서도 빠집니다.`) && del.mutate(c.id)}>삭제</Button>
              </div>) },
          ]} />
      </Panel>
      <Dialog open={!!f} onClose={() => setF(null)} title={f?.id ? "채널 수정" : "채널 추가"}
        footer={<><Button onClick={() => setF(null)}>취소</Button><Button variant="primary" disabled={!ready} loading={save.isPending} onClick={() => save.mutate(f!)}>저장</Button></>}>
        {f && <>
          <Field label="종류"><select className="input" value={f.kind} disabled={!!f.id} onChange={(e) => setF({ ...f, kind: e.target.value as ChannelKind })}>
            <option value="mattermost">Mattermost</option><option value="email">이메일</option></select></Field>
          <Field label="이름" required><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          {f.kind === "mattermost"
            ? <SecretField label="Incoming Webhook URL" isSet={f.webhookSet} value={f.webhook_url} onChange={(v) => setF({ ...f, webhook_url: v })} hint="URL에 토큰이 들어 있어 비밀값으로 다룹니다." />
            : <Field label="받는 사람" hint="이메일 주소를 쉼표나 줄바꿈으로 구분합니다. 보내는 메일 서버는 서버 환경 설정을 따릅니다." required><textarea className="input" rows={3} value={f.to} onChange={(e) => setF({ ...f, to: e.target.value })} /></Field>}
          <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>사용</Check>
        </>}
      </Dialog>
    </>
  );
}
