import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import type { Retention as R } from "../../api/types";
import { Loading, Panel, useSave } from "./parts";

export default function Retention() {
  const q = useApi<R>("/admin/retention");
  const [f, setF] = useState<R>({ raw_per_target: 20, raw_days: 90 });
  useEffect(() => { if (q.data) setF(q.data); }, [q.data]);
  const save = useSave(() => api.put("/admin/retention", f), { ok: "보관 기간을 저장했습니다.", invalidate: ["/admin/retention"] });
  return (
    <>
      <PageHeader title="보관 기간" description="스캔 원본 파일의 보관 한도입니다. 두 조건 중 하나라도 넘으면 오래된 원본부터 지웁니다. 집계 결과와 취약점 이력은 지우지 않습니다." />
      <Loading q={q} />
      {q.data && (
        <Panel title="원본 보관">
          <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <div className="two">
              <Field label="대상당 최대 개수" hint="대상(이미지/저장소)마다 최근 N개만 남깁니다. 기본 20."><input className="input" type="number" min={1} value={f.raw_per_target} onChange={(e) => setF({ ...f, raw_per_target: Number(e.target.value) })} /></Field>
              <Field label="최대 보관 일수" hint="이보다 오래된 원본은 지웁니다. 기본 90."><input className="input" type="number" min={1} value={f.raw_days} onChange={(e) => setF({ ...f, raw_days: Number(e.target.value) })} /></Field>
            </div>
            <div className="admin-actions"><Button type="submit" variant="primary" loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
    </>
  );
}
