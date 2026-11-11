import { NavLink } from "react-router-dom";
import { isSecurity } from "../api/hooks";
import type { Me } from "../api/types";
import Icon, { type IconName } from "./Icon";

export type NavItem = { to: string; label: string; icon: IconName; show?: (me?: Me) => boolean; end?: boolean };

/** Sidebar sections. Later pages add their entry here and a route in router.tsx. */
export const NAV: { title?: string; items: NavItem[] }[] = [
  {
    items: [
      { to: "/", label: "홈", icon: "home", end: true },
      { to: "/projects", label: "프로젝트", icon: "folder" },
      { to: "/findings", label: "취약점", icon: "bug" },
      { to: "/scan", label: "스캔하기", icon: "scan" },
    ],
  },
  {
    title: "검토",
    items: [
      { to: "/exceptions", label: "예외", icon: "shield", end: true },
      { to: "/exceptions/approvals", label: "예외 승인", icon: "inboxCheck", show: isSecurity },
      { to: "/advisories", label: "사내 Advisory", icon: "megaphone" },
      { to: "/reports", label: "보고서", icon: "fileText" },
    ],
  },
  { title: "시스템", items: [{ to: "/admin", label: "관리", icon: "settings", show: isSecurity }] },
];

export default function Sidebar({ me, onHelp, collapsed, onToggle }: { me?: Me; onHelp: () => void; collapsed: boolean; onToggle: () => void }) {
  const toggleLabel = collapsed ? "사이드바 펴기" : "사이드바 접기";
  return (
    <aside className="sidebar" id="sidebar">
      <div className="side-head">
      <NavLink to="/" className="brand" aria-label="JASCA 홈" title={collapsed ? "JASCA 홈" : undefined}>
        <span className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinejoin="round" strokeLinecap="round">
            <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6z" /><path d="M8 12h8" />
          </svg>
        </span>
        <span className="brand-text">
          <span className="brand-name">JASCA</span>
          <span className="brand-sub">취약점 관리</span>
        </span>
      </NavLink>
      <button type="button" className="side-toggle" aria-label={toggleLabel} aria-expanded={!collapsed} aria-controls="sidebar" title={`${toggleLabel} ( [ )`} onClick={onToggle}>
        <Icon name="panelLeft" size={16} />
      </button>
      </div>
      <nav aria-label="주 메뉴" className="nav">
        {NAV.map((sec, i) => {
          const items = sec.items.filter((it) => !it.show || it.show(me));
          if (!items.length) return null;
          return (
            <div key={i} className="nav-section">
              {sec.title && <p className="nav-title">{sec.title}</p>}
              <ul>
                {items.map((it) => (
                  <li key={it.to}>
                    {/* collapsed: the label stays for screen readers, the title is the tooltip */}
                    <NavLink to={it.to} end={it.end} className="nav-link" title={collapsed ? it.label : undefined}><Icon name={it.icon} /><span className="nav-label">{it.label}</span></NavLink>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>
      <button type="button" className="sidebar-help" onClick={onHelp} title={collapsed ? "단축키 ( ? )" : undefined}>
        <Icon name="keyboard" /><span className="nav-label">단축키</span><kbd>?</kbd>
      </button>
    </aside>
  );
}
