import { Link } from "react-router-dom";
import Empty from "../components/Empty";
import PageHeader from "../components/PageHeader";

export default function NotFound() {
  return (
    <>
      <PageHeader title="페이지를 찾을 수 없습니다" />
      <div className="panel">
        <Empty icon="search" title="주소가 바뀌었거나 볼 수 없는 페이지입니다"
          description="링크를 다시 확인하거나, 권한이 필요한 프로젝트라면 프로젝트 소유자에게 문의하세요."
          action={<Link to="/" className="btn btn-secondary">홈으로</Link>} />
      </div>
    </>
  );
}
