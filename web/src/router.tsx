import { createBrowserRouter, type RouteObject } from "react-router-dom";
import Layout from "./components/Layout";
import Home from "./pages/Home";
// Task 16: projects, findings, vulns, scans
import Findings from "./pages/Findings";
import ProjectDetail from "./pages/ProjectDetail";
import Projects from "./pages/Projects";
import Scan from "./pages/Scan";
import Vuln from "./pages/Vuln";
import "./styles/pages.css";
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
import Packages from "./pages/Packages";

// Signed-in pages (rendered inside Layout). Add a route here and, for top-level sections, an entry in Sidebar NAV.
export const pages: RouteObject[] = [
  { index: true, element: <Home /> },
  { path: "projects", element: <Projects /> },
  { path: "projects/:key/*", element: <ProjectDetail /> },
  { path: "findings", element: <Findings /> },
  { path: "packages", element: <Packages /> },
  { path: "vulns/:id", element: <Vuln /> },
  { path: "scans/:id", element: <Scan /> },
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
