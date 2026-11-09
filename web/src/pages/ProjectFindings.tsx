import { Link } from "react-router-dom";
import { useApi } from "../api/hooks";
import type { Project, Target } from "../api/types";
import CiSnippet from "../components/CiSnippet";
import { FindingsView } from "./Findings";

/** Results tab. Before the first scan it shows how to send one instead of an empty table. */
export default function ProjectFindings({ project }: { project: Project }) {
  const targets = useApi<Target[] | null>(`/projects/${project.key}/targets`);
  if (!project.last_scan_at) return <FirstScan project={project} />;
  return <FindingsView project={project.key} targets={targets.data ?? []} />;
}

export function FirstScan({ project }: { project: Project }) {
  return (
    <section className="panel onboard" aria-labelledby="h-first">
      <div className="onboard-head">
        <h2 id="h-first">첫 스캔을 보내세요</h2>
        <p className="muted">
          아직 이 프로젝트에 스캔이 없습니다. CI에서 Trivy 결과를 올리거나, <Link to={`/scan?project=${project.key}`}>스캔하기</Link>에서 파일을 올려 서버에서 스캔할 수 있습니다.
          {project.my_role === "owner" && <> CI용 토큰은 <Link to={`/projects/${project.key}/settings#tokens`}>설정 → API 토큰</Link>에서 만듭니다.</>}
        </p>
      </div>
      <CiSnippet projectKey={project.key} />
    </section>
  );
}
