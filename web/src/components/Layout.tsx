import { useEffect, useRef, useState, type FormEvent } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { useLogout, useMe } from "../api/hooks";
import type { Me } from "../api/types";
import { useHotkeys } from "../lib/hotkeys";
import { getTheme, setTheme, type ThemeMode } from "../lib/theme";
import Button from "./Button";
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
  const me = useMe();
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

  if (me.isPending || (me.isError && me.error.status === 401)) {
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
            <input ref={search} type="search" placeholder="CVE ID, 패키지, 프로젝트 검색" aria-label="전체 검색"
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
          <button type="button" className="menu-item" onClick={() => logout.mutate()} disabled={logout.isPending}>
            <Icon name="logout" />로그아웃
          </button>
        </div>
      )}
    </div>
  );
}
