import { useState } from "react";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useApi, useMe } from "../../api/hooks";
import { api } from "../../api/client";
import { SYSTEM_ROLE_LABEL, fmtDept, fmtRelative } from "../../lib/format";
import type { AdminUser, AdminUserPatch, SystemRole } from "../../api/types";
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
  const fixed = (u: AdminUser) => (u.id === me?.id ? "내 계정" : u.source === "local" ? "비상용 계정" : ""); // rows whose role and state cannot be changed
  const rows = (q.data ?? []).filter((u) => !f || [u.username, u.name, u.email, ...(u.depts ?? [])].some((s) => s?.toLowerCase().includes(f)));
  return (
    <>
      <PageHeader title="사용자·역할" description="역할은 시스템 전체 권한입니다. 여기서 바꾼 역할은 JASCA 안에서만 적용되고, 'Keycloak 역할 따름'으로 되돌리기 전까지 Keycloak 역할과 관계없이 유지됩니다." />
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
                <div className="muted">{fixed(u) ? `${fixed(u)}이라 바꿀 수 없습니다`
                  : u.source === "sso" && u.role_from_sso ? `지금 ${SYSTEM_ROLE_LABEL[u.system_role]} · 다음 Keycloak 로그인 때 다시 정해집니다` : "JASCA에서 정한 역할"}</div>
              </>) },
            { key: "last", header: "마지막 로그인", nowrap: true, render: (u) => (u.last_login_at ? fmtRelative(u.last_login_at) : <span className="muted">없음</span>) },
            { key: "active", header: "활성", align: "center", render: (u) => (
              <input type="checkbox" aria-label={`${u.username} 활성`} checked={u.active} disabled={!!fixed(u) || patch.isPending} title={fixed(u) ? `${fixed(u)}이라 바꿀 수 없습니다` : undefined}
                onChange={(e) => patch.mutate({ id: u.id, active: e.target.checked })} />) },
          ]} />
      </div>
    </>
  );
}
