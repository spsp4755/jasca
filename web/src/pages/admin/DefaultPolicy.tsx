import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import type { DefaultPolicy as P } from "../../api/types";
import { PolicyFields, policyCountError } from "../ProjectSettings";
import { Loading, Panel, useSave } from "./parts";

export default function DefaultPolicy() {
  const q = useApi<P>("/admin/default-policy");
  const [f, setF] = useState<P>({ enabled: false, min_severity: "HIGH", max_count: 0, new_only: false, fixable_only: false });
  useEffect(() => { if (q.data) setF(q.data); }, [q.data]);
  const save = useSave(() => api.put("/admin/default-policy", f), { ok: "기본 정책을 저장했습니다.", invalidate: ["/admin/default-policy"] });
  return (
    <>
      <PageHeader title="기본 정책" description="자체 정책을 정하지 않은 프로젝트에 적용됩니다. 기준을 넘는 스캔은 '정책 실패'로 표시됩니다." />
      <Loading q={q} />
      {q.data && (
        <Panel title="정책" meta="프로젝트 설정의 정책과 같은 방식입니다">
          <form className="form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <PolicyFields p={f} set={(patch) => setF({ ...f, ...patch })} label="기본 정책 사용 (끄면 자체 정책이 없는 프로젝트는 항상 정책 통과)" />
            <div className="form-actions"><Button type="submit" variant="primary" disabled={!!policyCountError(f)} loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
    </>
  );
}
