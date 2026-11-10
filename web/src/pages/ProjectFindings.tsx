import { Link } from "react-router-dom";
import { useApi } from "../api/hooks";
import type { Project, ScanPage, Target } from "../api/types";
import CiSnippet from "../components/CiSnippet";
import Icon from "../components/Icon";
import { FindingsView } from "./Findings";

/** Results tab. Before the first scan it shows how to send one instead of an empty table. */
export default function ProjectFindings({ project }: { project: Project }) {
  const targets = useApi<Target[] | null>(`/projects/${project.key}/targets`);
  if (!project.last_scan_at) return <FirstScan project={project} />;
  return <FindingsView project={project.key} targets={targets.data ?? []} />;
}

/** Shown while nothing has been scanned successfully. A scan that failed, was canceled or still runs is named, with a link. */
export function FirstScan({ project }: { project: Project }) {
  const newest = useApi<ScanPage>(`/projects/${project.key}/scans?limit=1`).data?.items?.[0];
  const last = newest?.status === "done" ? undefined : newest; // done: the project data on screen is a moment old
  return (
    <section className="panel onboard" aria-labelledby="h-first">
      <div className="onboard-head">
        <h2 id="h-first">첫 스캔을 보내세요</h2>
        {last && (
          <div className={`alert alert-${last.status === "failed" ? "danger" : "info"}`} style={{ margin: "8px 0" }}>
            <Icon name={last.status === "failed" ? "alert" : "info"} />
            <span>{last.status === "failed" ? "실패한 스캔이 있습니다." : last.status === "canceled" ? "취소된 스캔이 있습니다." : "진행 중인 스캔이 있습니다."}{" "}
              <Link to={`/scans/${last.id}`}>스캔 #{last.id} 보기</Link></span>
          </div>
        )}
        <p className="muted">
          {last ? "아직 끝난 스캔이 없습니다." : "아직 이 프로젝트에 스캔이 없습니다."} CI에서 Trivy 결과를 올리거나, <Link to={`/scan?project=${project.key}`}>스캔하기</Link>에서 파일을 올려 서버에서 스캔할 수 있습니다.
          {project.my_role === "owner" && <> CI용 토큰은 <Link to={`/projects/${project.key}/settings#tokens`}>설정 → API 토큰</Link>에서 만듭니다.</>}
        </p>
      </div>
      <CiSnippet projectKey={project.key} />
    </section>
  );
}
