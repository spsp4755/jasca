import { createBrowserRouter, type RouteObject } from "react-router-dom";
import Empty from "./components/Empty";
import Layout from "./components/Layout";
import PageHeader from "./components/PageHeader";
import Home from "./pages/Home";
// admin
import AdminLayout from "./pages/admin/AdminLayout";
import AdminAI from "./pages/admin/AI";
import AdminAudit from "./pages/admin/Audit";
import AdminChannels from "./pages/admin/Channels";
import AdminDefaultPolicy from "./pages/admin/DefaultPolicy";
import AdminHarbor from "./pages/admin/Harbor";
import AdminRecheck from "./pages/admin/Recheck";
import AdminRetention from "./pages/admin/Retention";
import AdminSSO from "./pages/admin/SSO";
import AdminSync from "./pages/admin/Sync";
import AdminTrivy from "./pages/admin/Trivy";
import AdminUsers from "./pages/admin/Users";
import Advisories from "./pages/Advisories";
import AdvisoryEdit from "./pages/AdvisoryEdit";
import Exceptions from "./pages/Exceptions";
import ProjectReport from "./pages/ProjectReport";
import Reports from "./pages/Reports";
import ScanNew from "./pages/ScanNew";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";

/** Stand-in until the page's task lands; replace the element in `pages` below. */
function Soon({ title }: { title: string }) {
  return (
    <>
      <PageHeader title={title} />
      <div className="panel"><Empty icon="clock" title="준비 중" description="이 화면은 곧 추가됩니다." /></div>
    </>
  );
}

// Signed-in pages (rendered inside Layout). Add a route here and, for top-level sections, an entry in Sidebar NAV.
export const pages: RouteObject[] = [
  { index: true, element: <Home /> },
  { path: "projects", element: <Soon title="프로젝트" /> },
  { path: "projects/:key/*", element: <Soon title="프로젝트" /> },
  { path: "findings", element: <Soon title="취약점" /> },
  { path: "vulns/:id", element: <Soon title="취약점 상세" /> },
  { path: "scans/:id", element: <Soon title="스캔 상세" /> },
  { path: "scan", element: <ScanNew /> },
  { path: "exceptions", element: <Exceptions /> },
  { path: "exceptions/approvals", element: <Exceptions /> },
  { path: "advisories", element: <Advisories /> },
  { path: "advisories/new", element: <AdvisoryEdit /> },
  { path: "advisories/:id", element: <AdvisoryEdit /> },
  { path: "reports", element: <Reports /> },
  { path: "reports/:key", element: <ProjectReport /> },
  // admin
  {
    path: "admin", element: <AdminLayout />,
    children: [
      { path: "users", element: <AdminUsers /> }, { path: "sso", element: <AdminSSO /> }, { path: "sync", element: <AdminSync /> },
      { path: "default-policy", element: <AdminDefaultPolicy /> }, { path: "trivy", element: <AdminTrivy /> }, { path: "recheck", element: <AdminRecheck /> },
      { path: "harbor", element: <AdminHarbor /> }, { path: "ai", element: <AdminAI /> }, { path: "channels", element: <AdminChannels /> },
      { path: "retention", element: <AdminRetention /> }, { path: "audit", element: <AdminAudit /> },
    ],
  },
  { path: "admin/*", element: <AdminLayout /> },
  { path: "*", element: <NotFound /> },
];

export const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  { path: "/", element: <Layout />, children: pages },
]);
