import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ApiError } from "../api/client";
import { useApi, useMe } from "../api/hooks";
import type { McpKey, McpKeyCreated, McpToolInfo } from "../api/types";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Empty from "../components/Empty";
import Field from "../components/Field";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import Table from "../components/Table";
import { useToast } from "../components/Toast";
import { copyText } from "../lib/clipboard";
import { SYSTEM_ROLE_LABEL, dateInput, daysUntil, endOfDayISO, fmtDate, fmtDateTime, fmtRelative } from "../lib/format";

const PATH = "/me/mcp-keys";
const mcpUrl = () => `${location.origin}/mcp`;
/** The MCP client entry for a key; the placeholder stands in until the person pastes their own key. */
export const mcpConfig = (key = "<MCP 키>") =>
  JSON.stringify({ mcpServers: { jasca: { type: "http", url: mcpUrl(), headers: { Authorization: `Bearer ${key}` } } } }, null, 2);

const GROUP_LABEL: Record<McpToolInfo["group"], string> = { user: "모든 사용자", security: "보안 담당", admin: "관리자" };

/** 사용자 메뉴 → MCP 키: a person's own keys, how to connect an agent with one, and what the agent can then do. */
export default function McpKeys() {
  const { data: me } = useMe();
  const q = useApi<McpKey[]>(PATH);
  const tools = useApi<McpToolInfo[]>("/me/mcp-tools");
  const qc = useQueryClient();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const revoke = useMutation<void, ApiError, number>({
    mutationFn: (id) => api.del(`${PATH}/${id}`),
    onSuccess: () => { toast("키를 폐기했습니다. 이 키를 쓰던 에이전트는 바로 연결이 끊깁니다.", "ok"); qc.invalidateQueries({ queryKey: [PATH] }); },
    onError: (e) => toast(e.message, "error"),
  });
  const copy = async (text: string, what: string) => toast((await copyText(text)) ? `${what} 복사했습니다.` : "복사하지 못했습니다. 직접 선택해 복사하세요.", "info");
  const now = Date.now();
  const dead = (k: McpKey) => !!k.revoked_at || new Date(k.expires_at).getTime() <= now;
  const rows = [...(q.data ?? [])].sort((a, b) => Number(dead(a)) - Number(dead(b)) || b.id - a.id);
  const usable = (tools.data ?? []).filter((t) => !t.disabled);
  const role = SYSTEM_ROLE_LABEL[me?.system_role ?? ""];

  return (
    <>
      <PageHeader title="MCP 키"
        description="AI 에이전트(MCP 클라이언트)가 내 계정의 권한으로 JASCA를 쓰도록 연결하는 개인 키입니다. 키로 한 일은 감사 기록에 내 이름으로 남습니다."
        actions={<Button variant="primary" icon="key" onClick={() => setCreating(true)}>키 만들기</Button>} />
      <div className="settings-main">
      {q.error && <div className="alert alert-danger" role="alert"><Icon name="alert" />{q.error.message}</div>}

      <section className="panel" aria-labelledby="h-keys">
        <div className="panel-head">
          <h2 id="h-keys">내 키</h2>
          <span className="panel-meta">키 값은 만들 때 한 번만 보입니다. 에이전트마다 따로 만들면 하나만 폐기할 수 있습니다.</span>
        </div>
        <Table<McpKey> caption="내 MCP 키" rows={rows} rowKey={(k) => k.id} loading={q.isPending} dense
          empty={<Empty compact icon="key" title="아직 만든 키가 없습니다" description="키를 만들면 아래 설정으로 에이전트를 연결할 수 있습니다."
            action={<Button variant="primary" onClick={() => setCreating(true)}>키 만들기</Button>} />}
          columns={[
            { key: "name", header: "이름", render: (k) => <span className="token-name"><b>{k.name}</b><span className="mono muted">{k.prefix}…</span></span> },
            { key: "kind", header: "할 수 있는 일", width: 150, render: (k) => (k.read_only
              ? <span className="tag tag-quiet" title="조회 도구만 쓸 수 있습니다">읽기 전용</span>
              : <span className="tag" title="내 권한으로 조회하고 바꿀 수 있습니다">조회·변경</span>) },
            { key: "used", header: "마지막 사용", width: 120, render: (k) => <span className="muted" title={fmtDateTime(k.last_used_at)}>{k.last_used_at ? fmtRelative(k.last_used_at) : "없음"}</span> },
            { key: "exp", header: "만료", width: 150, render: (k) => {
              if (k.revoked_at) return <span className="muted" title={fmtDateTime(k.revoked_at)}>폐기됨</span>;
              if (new Date(k.expires_at).getTime() <= now) return <span className="muted">만료됨</span>;
              const d = daysUntil(k.expires_at);
              return <span className={d <= 14 ? "due due-soon" : undefined} title={fmtDateTime(k.expires_at)}>{fmtDate(k.expires_at)}{d <= 14 && ` (D-${d})`}</span>;
            } },
            { key: "act", header: <span className="sr-only">폐기</span>, width: 80, align: "right", render: (k) => (!dead(k) && (
              <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === k.id}
                onClick={() => confirm(`"${k.name}" 키를 폐기할까요? 이 키를 쓰는 에이전트는 바로 연결이 끊깁니다.`) && revoke.mutate(k.id)}>폐기</Button>)) },
          ]} />
      </section>

      <section className="panel" aria-labelledby="h-connect">
        <div className="panel-head"><h2 id="h-connect">에이전트 연결</h2><span className="panel-meta">Streamable HTTP를 지원하는 MCP 클라이언트</span></div>
        <div className="panel-body">
          <div className="ci">
            <div className="secret-box">
              <code className="mono">{mcpUrl()}</code>
              <Button size="sm" icon="copy" onClick={() => copy(mcpUrl(), "주소를")}>주소 복사</Button>
            </div>
            <div className="ci-code">
              <pre aria-label="MCP 클라이언트 설정"><code>{mcpConfig()}</code></pre>
              <Button size="sm" icon="copy" className="ci-copy" onClick={() => copy(mcpConfig(), "설정을")}>복사</Button>
            </div>
            <ul className="ci-notes">
              <li>MCP 클라이언트의 설정 파일에 넣고 <code>&lt;MCP 키&gt;</code>를 만든 키 값으로 바꾸세요. 키를 만들면 값이 채워진 설정을 바로 복사할 수 있습니다.</li>
              <li>에이전트는 <b>지금의 내 권한</b>으로 일합니다. 내 역할이나 프로젝트 멤버 구성이 바뀌면 키를 다시 만들지 않아도 바로 반영되고, 계정이 비활성화되면 키도 멈춥니다.</li>
              <li>소스·이미지 파일은 MCP로 보낼 수 없어 에이전트가 <code>curl</code>로 올립니다. 에이전트를 실행하는 환경에 같은 키를 <code>JASCA_MCP_KEY</code> 환경 변수로 넣어 두세요. 명령은 에이전트가 <code>upload_commands</code> 도구로 받습니다.</li>
              <li>키는 비밀번호처럼 다루세요. 대화창이나 저장소에 붙여 넣지 말고, 유출이 의심되면 바로 폐기하세요.</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="panel" aria-labelledby="h-tools">
        <div className="panel-head">
          <h2 id="h-tools">에이전트가 쓸 수 있는 도구</h2>
          <span className="panel-meta">내 역할({role}) 기준 {usable.length}개{tools.data && usable.length < tools.data.length ? ` · 전체 ${tools.data.length}개` : ""}. 읽기 전용 키는 '조회' 도구만 씁니다.</span>
        </div>
        {tools.error && <div className="alert alert-danger" role="alert" style={{ margin: "0 18px 16px" }}><Icon name="alert" />{tools.error.message}</div>}
        <Table<McpToolInfo> caption="MCP 도구" rows={tools.data ?? []} rowKey={(t) => t.name} loading={tools.isPending} dense
          columns={[
            { key: "name", header: "도구", width: 210, mono: true, render: (t) => <span className={t.disabled ? "muted" : undefined}>{t.name}</span> },
            { key: "title", header: "에이전트가 할 수 있는 일", render: (t) => <span className={t.disabled ? "muted" : undefined}>{t.title}</span> },
            { key: "write", header: "종류", width: 80, render: (t) => <span className={`tag${t.write ? "" : " tag-quiet"}`}>{t.write ? "변경" : "조회"}</span> },
            { key: "group", header: "필요한 역할", width: 150, render: (t) => (t.disabled
              ? <span className="muted" title="내 역할로는 쓸 수 없는 도구입니다">{GROUP_LABEL[t.group]} 전용</span>
              : <span>{GROUP_LABEL[t.group]}</span>) },
          ]} />
      </section>
      </div>
      <McpKeyDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

/** Create a key. The plaintext is shown exactly once, here, together with the client configuration that carries it. */
function McpKeyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [readOnly, setReadOnly] = useState(false);
  const [expires, setExpires] = useState(dateInput(90));
  const [touched, setTouched] = useState(false);
  const create = useMutation<McpKeyCreated, ApiError, { name: string; read_only: boolean; expires_at: string }>({
    mutationFn: (b) => api.post<McpKeyCreated>(PATH, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: [PATH] }),
  });
  const close = () => { onClose(); create.reset(); setName(""); setReadOnly(false); setExpires(dateInput(90)); setTouched(false); };
  const nameErr = touched && !name.trim() ? "이름을 입력하세요. 예: 내 노트북 에이전트" : name.length > 100 ? "100자 이하로 입력하세요." : undefined;
  const dateErr = !expires || expires < dateInput(1) || expires > dateInput(364) ? "내일부터 1년 안의 날짜를 고르세요." : undefined;
  const submit = () => {
    setTouched(true);
    if (!name.trim() || nameErr || dateErr) return;
    create.mutate({ name: name.trim(), read_only: readOnly, expires_at: endOfDayISO(expires) });
  };
  const copy = async (text: string, what: string) => toast((await copyText(text)) ? `${what} 복사했습니다.` : "복사하지 못했습니다. 직접 선택해 복사하세요.", "info");
  const key = create.data?.key;

  if (key) {
    return (
      <Dialog open={open} onClose={close} title="키를 만들었습니다" size="md" dismissable={false}
        footer={<Button variant="primary" onClick={close}>복사했습니다, 닫기</Button>}>
        <div className="alert alert-warn" role="alert" style={{ margin: 0 }}>
          <Icon name="alert" />이 키는 지금 한 번만 보입니다. 창을 닫으면 다시 볼 수 없으니 에이전트 설정에 바로 넣으세요.
        </div>
        <div className="secret-box">
          <code className="mono">{key}</code>
          <Button size="sm" icon="copy" onClick={() => copy(key, "키를")}>복사</Button>
        </div>
        <div className="ci-code">
          <pre aria-label="키가 들어간 MCP 클라이언트 설정"><code>{mcpConfig(key)}</code></pre>
          <Button size="sm" icon="copy" className="ci-copy" onClick={() => copy(mcpConfig(key), "설정을")}>설정 복사</Button>
        </div>
        <p className="muted" style={{ fontSize: 13 }}>{fmtDate(endOfDayISO(expires))}까지 쓸 수 있습니다. 유출되면 MCP 키 목록에서 바로 폐기하세요.</p>
      </Dialog>
    );
  }
  return (
    <Dialog open={open} onClose={close} title="MCP 키 만들기" description="이 키로 연결한 에이전트는 내 계정의 권한으로 일합니다."
      footer={<><Button onClick={close}>취소</Button><Button variant="primary" loading={create.isPending} onClick={submit}>만들기</Button></>}>
      <form onSubmit={(e) => { e.preventDefault(); submit(); }} style={{ display: "contents" }}>
        <Field label="이름" required error={nameErr} hint={nameErr ? undefined : "어느 에이전트·기기에서 쓰는 키인지 알 수 있게 짓습니다."}>
          <input className="input" value={name} maxLength={100} autoFocus onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} />
        </Field>
        <fieldset className="field">
          <legend className="field-label">할 수 있는 일</legend>
          <div className="choice-list">
            <label className="choice">
              <input type="radio" name="mcp-kind" checked={!readOnly} onChange={() => setReadOnly(false)} />
              <span><b>조회·변경</b><span className="muted">내가 화면에서 할 수 있는 일을 에이전트도 합니다: 프로젝트 만들기, 업로드, 담당자·기한 지정, 예외 요청 등.</span></span>
            </label>
            <label className="choice">
              <input type="radio" name="mcp-kind" checked={readOnly} onChange={() => setReadOnly(true)} />
              <span><b>읽기 전용</b><span className="muted">조회만 합니다. 아무것도 바꾸거나 올릴 수 없어 처음 써 보는 에이전트에 안전합니다.</span></span>
            </label>
          </div>
        </fieldset>
        <Field label="만료일" required error={dateErr} hint={dateErr ? undefined : "최대 1년입니다. 그날 23:59에 만료됩니다."}>
          <input className="input" type="date" value={expires} min={dateInput(1)} max={dateInput(364)} onChange={(e) => setExpires(e.target.value)} />
        </Field>
        {create.isError && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" />{create.error.message}</div>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
