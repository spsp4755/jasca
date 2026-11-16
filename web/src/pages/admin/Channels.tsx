import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import Dialog from "../../components/Dialog";
import Table from "../../components/Table";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { fmtDate } from "../../lib/format";
import { useToast } from "../../components/Toast";
import type { ChannelKind, NotifyChannel, SMTPSettings, SMTPSettingsPut } from "../../api/types";
import { Link } from "react-router-dom";
import { Check, Loading, Panel, SecretField, useSave } from "./parts";
import type { OpsAlerts } from "./System";

const KIND: Record<ChannelKind, string> = { mattermost: "Mattermost", email: "이메일" };
type Form = { id?: number; kind: ChannelKind; name: string; enabled: boolean; webhook_url: string; webhookSet: boolean; to: string };
const EMPTY: Form = { kind: "mattermost", name: "", enabled: true, webhook_url: "", webhookSet: false, to: "" };

function SMTP() {
  const q = useApi<SMTPSettings>("/admin/smtp");
  const [f, setF] = useState<SMTPSettingsPut>({ host: "", port: 587, username: "", from: "", tls: "starttls" });
  const [pw, setPw] = useState("");
  useEffect(() => { if (q.data) { const { password_set: _p, ...rest } = q.data; setF(rest); setPw(""); } }, [q.data]);
  const save = useSave(() => api.put("/admin/smtp", { ...f, ...(pw ? { password: pw } : {}) }), { ok: "메일 서버 설정을 저장했습니다.", invalidate: ["/admin/smtp"] });
  return (
    <Panel title="메일 서버(SMTP)" meta="이메일 채널이 모두 이 서버로 보냅니다">
      <Loading q={q} />
      {q.data && (
        <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
          <div className="two">
            <Field label="호스트" hint="예: smtp.example.com"><input className="input" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} /></Field>
            <Field label="포트"><input className="input" type="number" min={1} max={65535} value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} /></Field>
          </div>
          <Field label="암호화"><select className="input" value={f.tls} onChange={(e) => setF({ ...f, tls: e.target.value as SMTPSettings["tls"] })}>
            <option value="starttls">STARTTLS (보통 587)</option><option value="tls">TLS (보통 465)</option><option value="none">사용 안 함</option></select></Field>
          <div className="two">
            <Field label="사용자 이름" hint="인증이 필요 없으면 비워 둡니다."><input className="input" autoComplete="off" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
            <SecretField label="비밀번호" isSet={q.data.password_set} value={pw} onChange={setPw} />
          </div>
          <Field label="보내는 사람" hint="예: JASCA <jasca@example.com>"><input className="input" value={f.from} onChange={(e) => setF({ ...f, from: e.target.value })} /></Field>
          <div className="admin-actions"><Button type="submit" variant="primary" loading={save.isPending}>저장</Button></div>
        </form>
      )}
    </Panel>
  );
}

/** Which channels hear about JASCA's own problems (opsCheck in system.go). */
function OpsAlertChannels({ channels }: { channels: NotifyChannel[] }) {
  const q = useApi<OpsAlerts>("/admin/ops-alerts");
  const [ids, setIds] = useState<number[]>([]);
  useEffect(() => { if (q.data) setIds(q.data.channel_ids); }, [q.data]);
  const save = useSave(() => api.put("/admin/ops-alerts", { channel_ids: ids }), { ok: "운영 알림을 받을 채널을 저장했습니다.", invalidate: ["/admin/ops-alerts"] });
  const dirty = !!q.data && [...ids].sort().join() !== [...q.data.channel_ids].sort().join();
  return (
    <Panel title="운영 알림" meta="JASCA 자체에 문제가 생겼을 때 운영자에게 알립니다">
      <p className="muted">취약점 DB가 오래됨, 저장 공간 부족, 알림 전송 실패, Keycloak 동기화 실패, 재평가 실패를 고른 채널로 보냅니다. 같은 문제는 한 번만 보내고, 취약점 DB가 오래된 경우만 일주일마다 다시 알립니다. 지금 상태는 <Link to="/admin/system">시스템 상태</Link>에서 봅니다.</p>
      <Loading q={q} />
      {q.data && (channels.length === 0 ? <p className="muted" style={{ margin: 0 }}>먼저 위에서 채널을 추가하세요.</p> : (
        <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
          <fieldset className="opt-set">
            <legend className="field-label">받을 채널</legend>
            <div className="stack" style={{ gap: 8 }}>
              {channels.map((c) => (
                <Check key={c.id} checked={ids.includes(c.id)} onChange={(v) => setIds(v ? [...ids, c.id] : ids.filter((x) => x !== c.id))}>
                  {c.name} <span className="muted">· {KIND[c.kind] ?? c.kind}{!c.enabled && " · 중지된 채널(보내지 않음)"}</span>
                </Check>
              ))}
            </div>
          </fieldset>
          <div className="admin-actions"><Button type="submit" variant="primary" disabled={!dirty} loading={save.isPending}>저장</Button>
            {ids.length === 0 && <span className="muted">고른 채널이 없으면 운영 알림을 보내지 않습니다.</span>}</div>
        </form>
      ))}
    </Panel>
  );
}

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
  const del = useSave((id: number) => api.del(`/admin/channels/${id}`), { ok: "삭제했습니다.", invalidate: ["/admin/channels", "/channels", "/admin/ops-alerts"] });
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
      <OpsAlertChannels channels={q.data ?? []} />
      <SMTP />
      <Dialog open={!!f} onClose={() => setF(null)} title={f?.id ? "채널 수정" : "채널 추가"}
        footer={<><Button onClick={() => setF(null)}>취소</Button><Button variant="primary" disabled={!ready} loading={save.isPending} onClick={() => save.mutate(f!)}>저장</Button></>}>
        {f && <>
          <Field label="종류"><select className="input" value={f.kind} disabled={!!f.id} onChange={(e) => setF({ ...f, kind: e.target.value as ChannelKind })}>
            <option value="mattermost">Mattermost</option><option value="email">이메일</option></select></Field>
          <Field label="이름" required><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          {f.kind === "mattermost"
            ? <SecretField label="Incoming Webhook URL" isSet={f.webhookSet} value={f.webhook_url} onChange={(v) => setF({ ...f, webhook_url: v })} hint="URL에 토큰이 들어 있어 비밀값으로 다룹니다." />
            : <Field label="받는 사람" hint="이메일 주소를 쉼표나 줄바꿈으로 구분합니다. 발송은 아래 &quot;메일 서버(SMTP)&quot; 설정을 씁니다." required><textarea className="input" rows={3} value={f.to} onChange={(e) => setF({ ...f, to: e.target.value })} /></Field>}
          <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>사용</Check>
        </>}
      </Dialog>
    </>
  );
}
