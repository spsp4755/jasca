import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { SEVERITY_LABEL } from "../../lib/format";
import type { DefaultPolicy as P, Severity } from "../../api/types";
import { Check, Loading, Panel, useSave } from "./parts";

const SEVS: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function DefaultPolicy() {
  const q = useApi<P>("/admin/default-policy");
  const [f, setF] = useState<P>({ enabled: false, min_severity: "HIGH", max_count: 0, new_only: false, fixable_only: false });
  useEffect(() => { if (q.data) setF(q.data); }, [q.data]);
  const save = useSave(() => api.put("/admin/default-policy", f), { ok: "기본 정책을 저장했습니다.", invalidate: ["/admin/default-policy"] });
  return (
    <>
      <PageHeader title="기본 정책" description="자체 정책이 없는 프로젝트에 적용되는 스캔 통과 기준입니다. 기준을 넘으면 스캔 결과가 '실패'로 표시됩니다." />
      <Loading q={q} />
      {q.data && (
        <Panel title="통과 기준">
          <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>기본 정책 사용</Check>
            <div className="two">
              <Field label="대상 최소 심각도" hint="이 등급 이상만 셉니다."><select className="input" value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value as Severity })}>
                {SEVS.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]} 이상</option>)}</select></Field>
              <Field label="허용 개수" hint="이 개수를 넘으면 실패합니다. 0이면 하나라도 있으면 실패."><input className="input" type="number" min={0} value={f.max_count} onChange={(e) => setF({ ...f, max_count: Number(e.target.value) })} /></Field>
            </div>
            <Check checked={f.new_only} onChange={(v) => setF({ ...f, new_only: v })}>직전 스캔보다 새로 생긴 취약점만 센다</Check>
            <Check checked={f.fixable_only} onChange={(v) => setF({ ...f, fixable_only: v })}>수정 버전이 있는 취약점만 센다</Check>
            <div className="admin-actions"><Button type="submit" variant="primary" loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
    </>
  );
}
