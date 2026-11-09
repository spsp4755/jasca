import { useEffect, useRef, useState, type FormEvent } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuthConfig, useLogout, useMe } from "../api/hooks";
import type { Me } from "../api/types";
import { useHotkeys } from "../lib/hotkeys";
import { getTheme, setTheme, type ThemeMode } from "../lib/theme";
import { useMutation } from "@tanstack/react-query";
import { ApiError, api, loginUrl } from "../api/client";
import Button from "./Button";
import Dialog from "./Dialog";
import Field from "./Field";
import { useToast } from "./Toast";
import Icon, { type IconName } from "./Icon";
import ShortcutHelp from "./ShortcutHelp";
import Sidebar from "./Sidebar";

const ROLE_LABEL: Record<string, string> = { admin: "관리자", security: "보안 담당", "": "일반 사용자" };
const THEMES: [ThemeMode, string, IconName][] = [["system", "시스템", "monitor"], ["light", "라이트", "sun"], ["dark", "다크", "moon"]];

/** "CVE-2024-1234" or "GHSA-…" opens the vuln page; anything else searches findings. */
export function searchTarget(q: string): string {
  const t = q.trim();
  if (/^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3})$/i.test(t)) return `/vulns/${encodeURIComponent(t.toUpperCase())}`;
  return `/findings?q=${encodeURIComponent(t)}`;
}

/** Signed-in shell: sidebar, top bar (search, theme, user menu), global hotkeys, then the page. */
export default function Layout() {
  const cfg = useAuthConfig(); // sets the display time zone; on failure times stay in Asia/Seoul
  const signedOut = cfg.data?.signed_in === false;
  const me = useMe(!cfg.isPending && !signedOut); // signed out: straight to the login page, no /me that 401s
  useEffect(() => { if (signedOut) location.assign(loginUrl()); }, [signedOut]);
  const navigate = useNavigate();
  const loc = useLocation();
  const [help, setHelp] = useState(false);
  const search = useRef<HTMLInputElement>(null);

  useHotkeys({
    "/": () => search.current?.focus(),
    "?": () => setHelp(true),
    "g h": () => navigate("/"),
    "g p": () => navigate("/projects"),
    "g f": () => navigate("/findings"),
    "g s": () => navigate("/scan"),
  });

  // move focus to the new page's heading for screen readers and keyboard users
  useEffect(() => { document.querySelector<HTMLElement>("main h1")?.focus({ preventScroll: true }); }, [loc.pathname]);

  if (me.isPending || cfg.isPending || signedOut || (me.isError && me.error.status === 401)) {
    return <div className="splash" aria-busy="true"><span className="brand-mark splash-mark" /><span className="sr-only">불러오는 중</span></div>;
  }
  if (me.isError) {
    return (
      <div className="splash">
        <div className="splash-error" role="alert">
          <Icon name="alert" size={20} />
          <p>{me.error.message}</p>
          <Button onClick={() => me.refetch()}>다시 시도</Button>
        </div>
      </div>
    );
  }

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    const q = search.current?.value.trim();
    if (!q) return;
    navigate(searchTarget(q));
    search.current?.blur();
  };

  return (
    <div className="app">
      <a href="#main" className="skip-link">본문으로 건너뛰기</a>
      <Sidebar me={me.data} onHelp={() => setHelp(true)} />
      <div className="app-main">
        <header className="topbar">
          <form role="search" className="search" onSubmit={onSearch}>
            <Icon name="search" />
            <input ref={search} type="search" placeholder="CVE ID, 패키지, 제목으로 결과 검색" aria-label="전체 검색"
              onKeyDown={(e) => { if (e.key === "Escape") e.currentTarget.blur(); }} />
            <kbd aria-hidden="true">/</kbd>
          </form>
          <div className="topbar-right">
            <ThemeButton />
            <UserMenu me={me.data} />
          </div>
        </header>
        <main id="main" className="content">
          <Outlet />
        </main>
      </div>
      <ShortcutHelp open={help} onClose={() => setHelp(false)} />
    </div>
  );
}

function ThemeButton() {
  const [mode, setMode] = useState(getTheme);
  const i = THEMES.findIndex(([m]) => m === mode);
  const [, cur, icon] = THEMES[i];
  const [next, nextLabel] = THEMES[(i + 1) % THEMES.length];
  const label = `화면 모드: ${cur} (누르면 ${nextLabel})`;
  return (
    <Button variant="ghost" icon={icon} aria-label={label} title={label} onClick={() => { setTheme(next); setMode(next); }} />
  );
}

function UserMenu({ me }: { me: Me }) {
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const logout = useLogout();
  useEffect(() => {
    if (!open) return;
    const off = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); ref.current?.querySelector("button")?.focus(); } };
    addEventListener("mousedown", off);
    addEventListener("keydown", esc);
    return () => { removeEventListener("mousedown", off); removeEventListener("keydown", esc); };
  }, [open]);
  const display = me.name || me.username;
  return (
    <div className="usermenu" ref={ref}>
      <button type="button" className="usermenu-btn" aria-haspopup="true" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <span className="avatar" aria-hidden="true">{display.slice(0, 1).toUpperCase()}</span>
        <span className="usermenu-name">{display}</span>
        <Icon name="chevronDown" size={14} />
      </button>
      {open && (
        <div className="menu" role="group" aria-label="사용자 메뉴">
          <div className="menu-head">
            <p className="menu-name">{display}</p>
            <p className="menu-sub">{me.username}{me.email && ` · ${me.email}`}</p>
            <p className="menu-role"><span className="tag">{ROLE_LABEL[me.system_role] ?? me.system_role}</span>
              {me.depts.slice(0, 2).map((d) => <span key={d} className="tag tag-quiet" title={d}>{d.split("/").pop()}</span>)}
            </p>
          </div>
          {me.source === "local" && (
            <button type="button" className="menu-item" onClick={() => { setOpen(false); setPw(true); }}>
              <Icon name="key" />비밀번호 바꾸기
            </button>
          )}
          <button type="button" className="menu-item" onClick={() => logout.mutate()} disabled={logout.isPending}>
            <Icon name="logout" />로그아웃
          </button>
        </div>
      )}
      <PasswordDialog open={pw} onClose={() => setPw(false)} />
    </div>
  );
}

/** Local accounts only (the bootstrap admin); SSO users change theirs in Keycloak. */
function PasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [again, setAgain] = useState("");
  const close = () => { setCur(""); setNw(""); setAgain(""); change.reset(); onClose(); };
  const change = useMutation<void, ApiError>({
    mutationFn: () => api.post<void>("/me/password", { current_password: cur, new_password: nw }),
    onSuccess: () => { toast("비밀번호를 바꿨습니다. 다른 기기의 로그인은 끝났습니다.", "ok"); close(); },
  });
  const bytes = new TextEncoder().encode(nw).length;
  const nwErr = nw && (bytes < 12 || bytes > 72) ? "12~72자(바이트)로 정하세요." : undefined;
  const againErr = again && again !== nw ? "새 비밀번호와 같지 않습니다." : undefined;
  const ok = cur && nw && !nwErr && again === nw;
  return (
    <Dialog open={open} onClose={close} title="비밀번호 바꾸기" description="바꾸면 이 브라우저를 뺀 다른 로그인은 모두 끝납니다."
      footer={<><Button onClick={close}>취소</Button><Button variant="primary" disabled={!ok} loading={change.isPending} onClick={() => change.mutate()}>바꾸기</Button></>}>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); if (ok) change.mutate(); }}>
        <Field label="현재 비밀번호" required><input className="input" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
        <Field label="새 비밀번호" required error={nwErr} hint={nwErr ? undefined : "12~72자"}><input className="input" type="password" autoComplete="new-password" value={nw} onChange={(e) => setNw(e.target.value)} /></Field>
        <Field label="새 비밀번호 확인" required error={againErr}><input className="input" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} /></Field>
        {change.error && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}>{change.error.message}</div>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
