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
  const save = useSave(() => api.put("/admin/retention", f), { ok: "보존 기간을 저장했습니다.", invalidate: ["/admin/retention"] });
  return (
    <>
      <PageHeader title="보존 기간" description="대상마다 최근 N개에도 들지 않고 보존 일수도 지난 스캔은 원본 보고서와 패키지 목록을 지웁니다(두 조건을 모두 넘어야 지움). 대상의 현재 패키지 목록, 스캔 기록, 결과와 취약점 이력은 지우지 않습니다." />
      <Loading q={q} />
      {q.data && (
        <Panel title="스캔 보존">
          <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <div className="two">
              <Field label="대상당 최근 개수" hint="대상(이미지/저장소)마다 최근 N개는 날짜와 상관없이 남깁니다. 기본 20."><input className="input" type="number" min={1} value={f.raw_per_target} onChange={(e) => setF({ ...f, raw_per_target: Number(e.target.value) })} /></Field>
              <Field label="보존 일수" hint="이 기간 안의 스캔은 개수와 상관없이 남깁니다. 기본 90."><input className="input" type="number" min={1} value={f.raw_days} onChange={(e) => setF({ ...f, raw_days: Number(e.target.value) })} /></Field>
            </div>
            <div className="admin-actions"><Button type="submit" variant="primary" loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
    </>
  );
}
