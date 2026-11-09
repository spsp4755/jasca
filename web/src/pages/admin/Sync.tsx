import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import Table from "../../components/Table";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { fmtDateTime } from "../../lib/format";
import type { DeptLogin, SyncRunResult, SyncStatus } from "../../api/types";
import { Check, Loading, Panel, SecretField, useSave } from "./parts";
import { useToast } from "../../components/Toast";

const SRC: Record<string, string> = {
  claim: "토큰 클레임", claim_empty: "클레임 비어 있음", admin_api: "Keycloak 관리 API", missing: "찾지 못함", error: "오류",
};

export default function Sync() {
  const q = useApi<SyncStatus>("/admin/sync");
  const logins = useApi<DeptLogin[]>("/admin/sync/logins");
  const toast = useToast();
  const [f, setF] = useState({ client_id: "", interval_min: 15, dept_attribute: "", dept_off: false });
  const [secret, setSecret] = useState("");
  useEffect(() => {
    if (q.data) { setF({ client_id: q.data.client_id, interval_min: q.data.interval_min || 15, dept_attribute: q.data.dept_attribute, dept_off: q.data.dept_off }); setSecret(""); }
  }, [q.data]);
  const save = useSave(() => api.put("/admin/sync", { ...f, ...(secret ? { client_secret: secret } : {}) }), { ok: "동기화 설정을 저장했습니다.", invalidate: ["/admin/sync"] });
  const run = useSave(() => api.post<SyncRunResult>("/admin/sync/run"), {
    invalidate: ["/admin/sync", "/admin/users"],
    onDone: (r) => (r.error ? toast(`동기화 실패: ${r.error}`, "error") : toast(`동기화했습니다. 그룹 ${r.groups}개, 사용자 ${r.users}명`, "ok")),
  });
  return (
    <>
      <PageHeader title="Keycloak 동기화" description="서비스 계정으로 그룹, 사용자, 부서를 주기적으로 가져옵니다. 프로젝트 멤버를 그룹 단위로 지정하려면 필요합니다."
        actions={<Button variant="secondary" icon="clock" loading={run.isPending} onClick={() => run.mutate(undefined)}>지금 동기화</Button>} />
      <Loading q={q} />
      {q.data && (
        <Panel title="동기화 설정" meta={q.data.last_run ? `마지막 실행 ${fmtDateTime(q.data.last_run)} · 그룹 ${q.data.groups} · 사용자 ${q.data.users}` : "아직 실행하지 않았습니다"}>
          {q.data.last_error && <div className="alert alert-danger" role="alert">마지막 오류: {q.data.last_error}</div>}
          <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <Field label="서비스 계정 Client ID" hint="Keycloak 클라이언트(service account 사용)에 view-users, view-realm 역할이 필요합니다."><input className="input" value={f.client_id} onChange={(e) => setF({ ...f, client_id: e.target.value })} /></Field>
            <SecretField label="서비스 계정 Secret" isSet={q.data.client_secret_set} value={secret} onChange={setSecret} />
            <div className="two">
              <Field label="동기화 주기 (분)"><input className="input" type="number" min={1} value={f.interval_min} onChange={(e) => setF({ ...f, interval_min: Number(e.target.value) })} /></Field>
              <Field label="부서 속성 이름" hint="토큰 클레임/사용자 속성 이름. 예: department"><input className="input" value={f.dept_attribute} onChange={(e) => setF({ ...f, dept_attribute: e.target.value })} /></Field>
            </div>
            <Check checked={f.dept_off} onChange={(v) => setF({ ...f, dept_off: v })}>부서 정보를 읽지 않음</Check>
            <div className="admin-actions"><Button type="submit" variant="primary" loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
      <Panel title="최근 SSO 로그인의 부서" meta="최근 20건 · 서버를 다시 시작하면 비워집니다">
        <p className="muted">부서가 비어 있거나 &quot;찾지 못함&quot;이면 부서 속성 이름과 Keycloak 매퍼 설정을 확인하세요.</p>
        <Table<DeptLogin> dense rowKey={(r) => `${r.user}${r.at}`} rows={logins.data ?? []} loading={logins.isLoading} caption="최근 SSO 로그인의 부서"
          empty={<span className="muted">아직 SSO 로그인 기록이 없습니다.</span>}
          columns={[
            { key: "at", header: "시각", nowrap: true, render: (r) => fmtDateTime(r.at) },
            { key: "user", header: "사용자", render: (r) => r.user },
            { key: "depts", header: "부서", render: (r) => (r.depts ?? []).join(", ") || <span className="muted">-</span> },
            { key: "source", header: "출처", nowrap: true, render: (r) => <span className={`tag${r.source === "error" || r.source === "missing" ? "" : " tag-quiet"}`}>{SRC[r.source] ?? r.source}</span> },
          ]} />
      </Panel>
    </>
  );
}
