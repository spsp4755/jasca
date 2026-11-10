import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { API_BASE, safeNext } from "../api/client";
import { useAuthConfig, useLocalLogin } from "../api/hooks";
import Button from "../components/Button";
import Field from "../components/Field";
import Icon from "../components/Icon";
import { SEVERITY_LABEL } from "../lib/format";
import { SEVERITIES } from "../api/types";

// Error codes from POST /auth/local and from the SSO callback redirect (/login?error=<code>). A code missing here
// shows the server's own message: "locked" says how many minutes are left.
const ERRORS: Record<string, string> = {
  unauthorized: "아이디 또는 비밀번호가 올바르지 않습니다.",
  invalid_credentials: "아이디 또는 비밀번호가 올바르지 않습니다.",
  bad_credentials: "아이디 또는 비밀번호가 올바르지 않습니다.",
  inactive: "비활성화된 계정입니다. 관리자에게 문의하세요.",
  disabled: "비활성화된 계정입니다. 관리자에게 문의하세요.",
  rate_limited: "로그인 요청이 너무 많습니다. 잠시 후 다시 시도하세요.",
  csrf: "보안 확인에 실패했습니다. 페이지를 새로고침한 뒤 다시 시도하세요.",
  sso: "Keycloak에 연결하지 못했습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.",
  sso_disabled: "Keycloak 로그인이 설정되지 않았습니다.",
  expired: "로그인 시간이 지나 다시 로그인해야 합니다.", // set by loginUrl() when a signed-in page got a 401
  state: "로그인 요청을 확인하지 못했습니다. 다시 로그인하세요.",
  forbidden: "이 서비스를 사용할 권한이 없습니다. 관리자에게 문의하세요.",
  conflict: "같은 아이디의 로컬 계정이 있어 Keycloak으로 로그인할 수 없습니다. 관리자에게 문의하세요.",
  identity: "같은 아이디를 쓰던 다른 Keycloak 계정이 JASCA에 남아 있습니다. 관리자에게 기존 계정을 비활성화해 달라고 요청하세요.",
};
const errorText = (code: string, fallback?: string) => ERRORS[code] ?? fallback ?? "로그인하지 못했습니다. 다시 시도하세요.";

export default function Login() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const cfg = useAuthConfig();
  const login = useLocalLogin();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [missing, setMissing] = useState<{ u?: string; p?: string }>({});

  const next = safeNext(params.get("next"));
  const wantLocal = params.get("local") === "1";
  // Without SSO configured the local form is the only way in (first start, bootstrap admin).
  const showLocal = wantLocal || (cfg.isSuccess && !cfg.data.sso_enabled);
  const urlError = params.get("error");
  const error = login.isError ? errorText(login.error.code, login.error.message)
    : urlError ? errorText(urlError)
    : cfg.isError ? cfg.error.message : null;

  useEffect(() => { document.title = "로그인 · JASCA"; }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const m = { u: username.trim() ? undefined : "아이디를 입력하세요.", p: password ? undefined : "비밀번호를 입력하세요." };
    setMissing(m);
    if (m.u || m.p) return;
    login.mutate({ username: username.trim(), password }, { onSuccess: () => navigate(next, { replace: true }), onError: () => setPassword("") });
  };

  return (
    <div className="login">
      <section className="login-aside" aria-hidden="true">
        <div className="login-brand">
          <span className="brand-mark brand-mark-lg">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinejoin="round" strokeLinecap="round">
              <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6z" /><path d="M8 12h8" />
            </svg>
          </span>
          JASCA
        </div>
        <div className="login-copy">
          <p className="login-eyebrow">취약점 관리</p>
          <p className="login-headline">스캔 결과를 한곳에 모으고,<br />조치될 때까지 추적합니다.</p>
        </div>
        <ul className="login-spectrum">
          {SEVERITIES.map((s) => (
            <li key={s} className={`spec-${s.toLowerCase()}`}><span />{SEVERITY_LABEL[s]}</li>
          ))}
        </ul>
      </section>

      <main className="login-main">
        <div className="login-panel">
          <h1>로그인</h1>
          <p className="login-sub">{showLocal ? "로컬 계정으로 로그인합니다. 비상용입니다." : "회사 계정(Keycloak)으로 로그인합니다."}</p>

          {error && (!login.isError && urlError === "expired" // not a failure: the session simply ran out
            ? <div className="alert alert-info" role="status"><Icon name="info" />{error}</div>
            : <div className="alert alert-danger" role="alert"><Icon name="alert" />{error}</div>)}

          {cfg.isPending ? (
            <div className="login-loading"><span className="spinner" aria-hidden="true" /> 확인 중</div>
          ) : showLocal ? (
            <form onSubmit={submit} noValidate className="login-form">
              <Field label="아이디" error={missing.u}>
                <input className="input input-lg" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} />
              </Field>
              <Field label="비밀번호" error={missing.p}>
                <input className="input input-lg" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              <Button type="submit" variant="primary" className="btn-block btn-lg" loading={login.isPending}>로그인</Button>
              {cfg.data?.sso_enabled && <Link className="login-switch" to={`/login?next=${encodeURIComponent(next)}`}>Keycloak 로그인으로 돌아가기</Link>}
            </form>
          ) : (
            <div className="login-form">
              <a className="btn btn-primary btn-block btn-lg" href={`${API_BASE}/auth/sso/start?next=${encodeURIComponent(next)}`}>
                <Icon name="key" />Keycloak으로 로그인
              </a>
              <p className="login-note">계정이 없거나 로그인이 되지 않으면 보안 담당자에게 문의하세요.</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
