import { useState } from "react";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useApi, useMe } from "../../api/hooks";
import { api } from "../../api/client";
import Button from "../../components/Button";
import { SYSTEM_ROLE_LABEL, fmtDate, fmtDateTime, fmtDept, fmtRelative } from "../../lib/format";
import type { AdminMcpKey, AdminUser, AdminUserPatch, SystemRole } from "../../api/types";
import { Loading, useSave } from "./parts";

export default function Users() {
  const q = useApi<AdminUser[]>("/admin/users");
  const { data: me } = useMe();
  const [filter, setFilter] = useState("");
  const patch = useSave(({ id, ...b }: AdminUserPatch & { id: number }) => api.patch(`/admin/users/${id}`, b), { ok: "저장했습니다.", invalidate: ["/admin/users"] });
  const f = filter.trim().toLowerCase();
  // "sso" in the role select hands the role back to Keycloak; a stray arrow key must not change a role, so every change asks first
  const setRole = (u: AdminUser, v: string) => {
    const label = v === "sso" ? "Keycloak 역할 따름" : SYSTEM_ROLE_LABEL[v as SystemRole];
    if (confirm(`${u.name || u.username}(${u.username}) 사용자의 역할을 바꿉니다.\n새 역할: ${label}\n\n계속할까요?`)) patch.mutate(v === "sso" ? { id: u.id, role_from_sso: true } : { id: u.id, system_role: v as SystemRole });
  };
  const fixed = (u: AdminUser) => (u.id === me?.id ? "내 계정" : u.source === "local" ? "비상용 공용 계정" : ""); // rows whose role cannot be changed
  // the shared local admin: its role is fixed, but another administrator switches it off once people use their own accounts
  const setActive = (u: AdminUser, on: boolean) => {
    if (u.source === "local" && !confirm(on
      ? "공용 admin 계정을 다시 켭니다. 비상시가 끝나면 다시 꺼 두세요.\n\n계속할까요?"
      : "공용 admin 계정을 끕니다. admin으로는 로그인할 수 없게 되고, 접속 중이던 admin은 바로 로그아웃됩니다.\n\nKeycloak 장애로 아무도 로그인하지 못하게 되면 서버에서 명령으로 다시 켜야 합니다(관리자 가이드 참고).\n\n계속할까요?")) return;
    patch.mutate({ id: u.id, active: on });
  };
  const rows = (q.data ?? []).filter((u) => !f || [u.username, u.name, u.email, ...(u.depts ?? [])].some((s) => s?.toLowerCase().includes(f)));
  return (
    <>
      <PageHeader title="사용자·역할" description="역할은 시스템 전체 권한입니다. 여기서 바꾼 역할은 JASCA 안에서만 적용되고, 'Keycloak 역할 따름'으로 되돌리기 전까지 Keycloak 역할과 관계없이 유지됩니다. 로컬 admin은 여럿이 함께 쓰는 비상용 계정입니다. 개인 계정에 관리자 역할을 준 뒤, 그 계정으로 로그인해 admin의 활성을 꺼 두세요." />
      <Loading q={q} />
      <div className="panel">
        <div className="panel-head">
          <h2>사용자 {q.data ? `(${rows.length})` : ""}</h2>
          <input className="input" style={{ width: 240 }} placeholder="이름, 아이디, 이메일, 부서 검색" aria-label="사용자 검색" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        <Table<AdminUser> dense rowKey={(u) => u.id} rows={rows} loading={q.isLoading} caption="사용자 목록" empty={<span className="muted">사용자가 없습니다.</span>}
          columns={[
            { key: "name", header: "사용자", render: (u) => <><b>{u.name || u.username}</b><div className="muted">{u.username}{u.email && ` · ${u.email}`}</div></> },
            { key: "source", header: "계정", nowrap: true, render: (u) => <span className="tag tag-quiet">{u.source === "sso" ? "SSO" : "로컬"}</span> },
            { key: "depts", header: "부서", render: (u) => (u.depts ?? []).map(fmtDept).join(", ") || <span className="muted">-</span> },
            { key: "role", header: "역할", nowrap: true, render: (u) => (
              <>
                <select className="input" aria-label={`${u.username} 역할`} value={u.role_from_sso && u.source === "sso" ? "sso" : u.system_role}
                  disabled={!!fixed(u) || patch.isPending} onChange={(e) => setRole(u, e.target.value)}>
                  {u.source === "sso" && <option value="sso">Keycloak 역할 따름</option>}
                  {(["", "security", "admin"] as const).map((r) => <option key={r} value={r}>{SYSTEM_ROLE_LABEL[r]}</option>)}
                </select>
                <div className="muted">{fixed(u) ? `${fixed(u)}이라 ${u.source === "local" && u.id !== me?.id ? "역할은 " : ""}바꿀 수 없습니다`
                  : u.source === "sso" && u.role_from_sso ? `지금 ${SYSTEM_ROLE_LABEL[u.system_role]} · 다음 Keycloak 로그인 때 다시 정해집니다` : "JASCA에서 정한 역할"}</div>
              </>) },
            { key: "last", header: "마지막 로그인", nowrap: true, render: (u) => (u.last_login_at ? fmtRelative(u.last_login_at) : <span className="muted">없음</span>) },
            { key: "active", header: "활성", align: "center", render: (u) => (
              <input type="checkbox" aria-label={`${u.username} 활성`} checked={u.active} disabled={u.id === me?.id || patch.isPending} title={u.id === me?.id ? "내 계정이라 바꿀 수 없습니다" : undefined}
                onChange={(e) => setActive(u, e.target.checked)} />) },
          ]} />
      </div>
      <McpKeys filter={f} />
    </>
  );
}

/** Everyone's personal MCP keys: who has an agent connected, and the way to cut one off. The user search narrows it too. */
function McpKeys({ filter }: { filter: string }) {
  const q = useApi<AdminMcpKey[]>("/admin/mcp-keys");
  const revoke = useSave((id: number) => api.del(`/admin/mcp-keys/${id}`), { ok: "키를 폐기했습니다.", invalidate: ["/admin/mcp-keys"] });
  const now = Date.now();
  const state = (k: AdminMcpKey) => (k.revoked_at ? "폐기됨" : new Date(k.expires_at).getTime() <= now ? "만료됨" : !k.user_active ? "계정 비활성" : "");
  const rows = (q.data ?? []).filter((k) => !filter || [k.username, k.user_name, k.name].some((s) => s?.toLowerCase().includes(filter)))
    .sort((a, b) => Number(!!state(a)) - Number(!!state(b)) || b.id - a.id);
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>MCP 키 {q.data ? `(${rows.length})` : ""}</h2>
        <span className="panel-meta">사용자가 AI 에이전트 연결용으로 만든 개인 키입니다. 키는 그 사용자의 권한으로 동작하고, 계정을 비활성화하면 함께 멈춥니다.</span>
      </div>
      <Loading q={q} />
      <Table<AdminMcpKey> dense rowKey={(k) => k.id} rows={rows} loading={q.isLoading} caption="전체 사용자의 MCP 키" empty={<span className="muted">만들어진 키가 없습니다.</span>}
        columns={[
          { key: "user", header: "사용자", render: (k) => <><b>{k.user_name || k.username}</b><div className="muted">{k.username}</div></> },
          { key: "name", header: "키", render: (k) => <span className="token-name"><b>{k.name}</b><span className="mono muted">{k.prefix}…</span></span> },
          { key: "kind", header: "종류", nowrap: true, render: (k) => <span className={`tag${k.read_only ? " tag-quiet" : ""}`}>{k.read_only ? "읽기 전용" : "조회·변경"}</span> },
          { key: "used", header: "마지막 사용", nowrap: true, render: (k) => (k.last_used_at ? <span title={fmtDateTime(k.last_used_at)}>{fmtRelative(k.last_used_at)}</span> : <span className="muted">없음</span>) },
          { key: "exp", header: "만료", nowrap: true, render: (k) => (state(k) ? <span className="muted">{state(k)}</span> : fmtDate(k.expires_at)) },
          { key: "act", header: <span className="sr-only">폐기</span>, align: "right", render: (k) => (!k.revoked_at && new Date(k.expires_at).getTime() > now && (
            <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === k.id}
              onClick={() => confirm(`${k.user_name || k.username}(${k.username}) 사용자의 "${k.name}" 키를 폐기할까요? 이 키를 쓰는 에이전트는 바로 연결이 끊깁니다.`) && revoke.mutate(k.id)}>폐기</Button>)) },
        ]} />
    </div>
  );
}
