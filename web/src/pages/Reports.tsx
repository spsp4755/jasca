import PageHeader from "../components/PageHeader";
import Table from "../components/Table";
import Empty from "../components/Empty";
import { useApi, useAuthConfig } from "../api/hooks";
import type { Project } from "../api/types";
import { projectColumns } from "./Projects";

const cols = projectColumns((p) => `/reports/${encodeURIComponent(p.key)}`);

export default function Reports() {
  const q = useApi<Project[]>("/projects");
  const ai = useAuthConfig().data?.ai_enabled;
  return (
    <>
      <PageHeader title="보고서" description={`프로젝트를 고르면 인쇄할 수 있는 현황 보고서${ai ? "와 AI 요약 보고서" : ""}를 볼 수 있습니다.`} />
      {q.error && <div className="alert alert-danger" role="alert">{q.error.message}</div>}
      <div className="panel"><Table columns={cols} rows={q.data ?? []} rowKey={(p) => p.key} loading={q.isLoading} caption="프로젝트 선택"
        empty={<Empty title="볼 수 있는 프로젝트가 없습니다" description="프로젝트를 만들거나 멤버로 초대받으면 여기에 나타납니다." />} /></div>
    </>
  );
}
