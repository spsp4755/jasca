import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import type { SSOSettings, SSOSettingsPut } from "../../api/types";
import { Check, Loading, Panel, SecretField, useSave } from "./parts";

export default function SSO() {
  const q = useApi<SSOSettings>("/admin/sso");
  const [f, setF] = useState<SSOSettingsPut>({ issuer: "", client_id: "", admin_role: "", security_role: "", public_url: "", enabled: false });
  const [secret, setSecret] = useState("");
  useEffect(() => {
    if (q.data) { const { client_secret_set: _s, ...rest } = q.data; setF(rest); setSecret(""); }
  }, [q.data]);
  const save = useSave(() => api.put("/admin/sso", { ...f, ...(secret ? { client_secret: secret } : {}) }), { ok: "SSO 설정을 저장했습니다.", invalidate: ["/admin/sso", "/auth/config"] });
  const set = (k: keyof SSOSettingsPut) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return (
    <>
      <PageHeader title="SSO (Keycloak)" description="OIDC로 로그인합니다. 끄면 로컬 계정으로만 로그인할 수 있습니다." />
      <Loading q={q} />
      {q.data && (
        <Panel title="연결 설정">
          <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>SSO 로그인 사용</Check>
            <Field label="Issuer URL" hint="예: https://keycloak.example.com/realms/corp" required><input className="input" value={f.issuer} onChange={set("issuer")} /></Field>
            <Field label="Client ID" required><input className="input" value={f.client_id} onChange={set("client_id")} /></Field>
            <SecretField label="Client Secret" isSet={q.data.client_secret_set} value={secret} onChange={setSecret} />
            <div className="two">
              <Field label="관리자 역할" hint="이 Keycloak 역할을 가진 사용자는 시스템 관리자가 됩니다."><input className="input" value={f.admin_role} onChange={set("admin_role")} /></Field>
              <Field label="보안 담당 역할" hint="이 역할을 가진 사용자는 보안 담당이 됩니다."><input className="input" value={f.security_role} onChange={set("security_role")} /></Field>
            </div>
            <Field label="사이트 주소" hint="리다이렉트 주소(/api/v1/auth/sso/callback)의 기준입니다. 비우면 브라우저가 접속한 주소를 씁니다."><input className="input" value={f.public_url} onChange={set("public_url")} placeholder="https://jasca.example.com" /></Field>
            <div className="admin-actions"><Button type="submit" variant="primary" loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
    </>
  );
}
