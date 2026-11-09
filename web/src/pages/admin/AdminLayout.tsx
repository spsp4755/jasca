import { NavLink, Navigate, Outlet, useLocation } from "react-router-dom";
import Empty from "../../components/Empty";
import PageHeader from "../../components/PageHeader";
import { isAdmin, isSecurity, useMe } from "../../api/hooks";
import "../../styles/admin.css";

// to: path under /admin; security: visible to security as well as admin.
const ITEMS: { to: string; label: string; security?: boolean; group?: string }[] = [
  { to: "users", label: "사용자·역할", group: "계정" },
  { to: "sso", label: "SSO (Keycloak)" },
  { to: "sync", label: "Keycloak 동기화" },
  { to: "default-policy", label: "기본 정책", security: true, group: "스캔" },
  { to: "trivy", label: "Trivy DB" },
  { to: "recheck", label: "재평가" },
  { to: "harbor", label: "Harbor", group: "연동" },
  { to: "ai", label: "AI" },
  { to: "channels", label: "알림 채널" },
  { to: "retention", label: "보존 기간", group: "운영" },
  { to: "audit", label: "감사 로그" },
];

export default function AdminLayout() {
  const { data: me } = useMe();
  const { pathname } = useLocation();
  const visible = ITEMS.filter((i) => (i.security ? isSecurity(me) : isAdmin(me)));
  const cur = ITEMS.find((i) => pathname === `/admin/${i.to}` || pathname.startsWith(`/admin/${i.to}/`));
  if (!visible.length) return <><PageHeader title="관리" /><div className="panel"><Empty icon="alert" title="권한이 없습니다" description="관리 화면은 관리자 또는 보안 담당만 볼 수 있습니다." /></div></>;
  if (!cur) return <Navigate to={`/admin/${visible[0].to}`} replace />;
  const allowed = visible.includes(cur);
  return (
    <div className="admin">
      <nav className="admin-nav" aria-label="관리 메뉴">
        {visible.map((i) => (
          <div key={i.to} style={{ display: "contents" }}>
            {i.group && <p className="nav-title">{i.group}</p>}
            <NavLink to={i.to}>{i.label}</NavLink>
          </div>
        ))}
      </nav>
      <div className="admin-main">
        {allowed ? <Outlet /> : <><PageHeader title={cur.label} /><div className="panel"><Empty icon="alert" title="권한이 없습니다" description="이 화면은 관리자만 볼 수 있습니다." /></div></>}
      </div>
    </div>
  );
}
