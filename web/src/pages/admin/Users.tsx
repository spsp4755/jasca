import { useState } from "react";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useApi, useMe } from "../../api/hooks";
import { api } from "../../api/client";
import { fmtRelative } from "../../lib/format";
import type { AdminUser, AdminUserPatch, SystemRole } from "../../api/types";
import { Loading, useSave } from "./parts";

export default function Users() {
  const q = useApi<AdminUser[]>("/admin/users");
  const { data: me } = useMe();
  const [filter, setFilter] = useState("");
  const patch = useSave(({ id, ...b }: AdminUserPatch & { id: number }) => api.patch(`/admin/users/${id}`, b), { ok: "저장했습니다.", invalidate: ["/admin/users"] });
  const f = filter.trim().toLowerCase();
  const rows = (q.data ?? []).filter((u) => !f || [u.username, u.name, u.email, ...(u.depts ?? [])].some((s) => s?.toLowerCase().includes(f)));
  return (
    <>
      <PageHeader title="사용자·역할" description="역할은 시스템 전체 권한입니다. SSO 역할 매핑으로 정해진 사용자는 로그인 때마다 다시 계산되므로 여기서 바꿀 수 없습니다." />
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
            { key: "depts", header: "부서", render: (u) => (u.depts ?? []).join(", ") || <span className="muted">-</span> },
            { key: "role", header: "역할", nowrap: true, render: (u) => (
              <>
                <select className="input" aria-label={`${u.username} 역할`} value={u.system_role} disabled={u.role_from_sso || u.id === me?.id || patch.isPending}
                  onChange={(e) => patch.mutate({ id: u.id, system_role: e.target.value as SystemRole })}>
                  <option value="">일반 사용자</option><option value="security">보안 담당</option><option value="admin">관리자</option>
                </select>
                {u.role_from_sso && <div className="muted">SSO 역할로 지정됨</div>}
              </>) },
            { key: "last", header: "마지막 로그인", nowrap: true, render: (u) => (u.last_login_at ? fmtRelative(u.last_login_at) : <span className="muted">없음</span>) },
            { key: "active", header: "활성", align: "center", render: (u) => (
              <input type="checkbox" aria-label={`${u.username} 활성`} checked={u.active} disabled={u.id === me?.id || patch.isPending}
                onChange={(e) => patch.mutate({ id: u.id, active: e.target.checked })} />) },
          ]} />
      </div>
    </>
  );
}
