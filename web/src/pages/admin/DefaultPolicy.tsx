import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import { useToast } from "../../components/Toast";
import { isAdmin, useApi, useMe } from "../../api/hooks";
import { api } from "../../api/client";
import type { DefaultPolicy as P, SLA, Severity } from "../../api/types";
import { SEVERITY_LABEL } from "../../lib/format";
import { refreshTriage } from "../FindingTriage";
import { PolicyFields, policyCountError } from "../ProjectSettings";
import { Check, Loading, Panel, useSave } from "./parts";

export default function DefaultPolicy() {
  const admin = isAdmin(useMe().data); // the deadline setting is the admin's; security users see the policy only
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
            <PolicyFields p={f} set={(patch) => setF({ ...f, ...patch })} label="기본 정책 사용 (끄면 자체 정책이 없는 프로젝트는 스캔을 판정하지 않음 · CI에는 통과로 응답)" />
            <div className="form-actions"><Button type="submit" variant="primary" disabled={!!policyCountError(f)} loading={save.isPending}>저장</Button></div>
          </form>
        </Panel>
      )}
      {admin && <DeadlinePanel />}
    </>
  );
}

const DUE_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]; // UNKNOWN never has a deadline
const daysError = (d: number | null | undefined) => (d == null || (Number.isInteger(d) && d >= 1 && d <= 3650) ? "" : "기한은 1일부터 3650일까지의 정수로 입력하세요.");

/** 조치 기한: how many days a finding of each severity may stay open. One setting for every project (GET/PUT /admin/sla, admin only). */
function DeadlinePanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useApi<SLA>("/admin/sla");
  const [f, setF] = useState<SLA | null>(null);
  useEffect(() => { if (q.data) setF(q.data); }, [q.data]);
  const save = useSave(() => api.put<SLA & { changed: number }>("/admin/sla", f!), {
    invalidate: ["/admin/sla"],
    onDone: (r) => { toast(r.changed ? `조치 기한을 저장했습니다. 열린 결과 ${r.changed}건의 기한이 바뀌었습니다.` : "조치 기한을 저장했습니다. 기한이 바뀐 결과는 없습니다.", "ok"); void refreshTriage(qc); },
  });
  const err = f ? DUE_SEVERITIES.map((s) => daysError(f.days[s])).find(Boolean) : "";
  const submit = () => {
    if (confirm("저장하면 지금 열려 있는 결과의 기한을 새 기준으로 다시 계산합니다. 직접 정한 기한은 그대로 둡니다.\n\n계속할까요?")) save.mutate(undefined);
  };
  return (
    <>
      <Loading q={q} />
      {f && (
        <Panel title="조치 기한" meta="심각도별로 며칠 안에 조치해야 하는지 · 모든 프로젝트 공통">
          <form className="form" onSubmit={(e) => { e.preventDefault(); submit(); }}>
            <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>조치 기한 사용 (끄면 정책으로 정해진 기한이 모두 사라지고, 사람이 직접 정한 기한만 남음)</Check>
            <fieldset className="due-days" disabled={!f.enabled}>
              <legend className="sr-only">심각도별 기한</legend>
              {DUE_SEVERITIES.map((s) => {
                const d = f.days[s] ?? null;
                return (
                  <div key={s} className="due-days-row">
                    <span className="due-days-sev"><span className={`sev-dot dot-${s.toLowerCase()}`} aria-hidden="true" />{SEVERITY_LABEL[s]}</span>
                    <input className="input input-sm num" type="number" min={1} max={3650} step={1} aria-label={`${s} 기한(일)`} aria-invalid={daysError(d) ? true : undefined}
                      disabled={d === null} value={d === null || Number.isNaN(d) ? "" : d}
                      onChange={(e) => setF({ ...f, days: { ...f.days, [s]: e.target.value === "" ? NaN : Number(e.target.value) } })} />
                    <span>일 안에 조치</span>
                    <label className="check-row"><input type="checkbox" checked={d === null} onChange={(e) => setF({ ...f, days: { ...f.days, [s]: e.target.checked ? null : q.data?.days[s] ?? 30 } })} />기한 없음</label>
                  </div>
                );
              })}
            </fieldset>
            {err && <p className="field-err" role="alert">{err}</p>}
            <p className="side-note">기한은 결과가 열림이 된 날부터 셉니다. 처음 발견된 날, 스캔에서 다시 나타나 다시 열린 날, 예외가 끝나 다시 열린 날이 그 시작입니다. UNKNOWN에는 기한을 두지 않습니다.
              저장하면 지금 열려 있는 결과의 기한도 새 기준으로 다시 계산하며, 결과 화면에서 사람이 직접 정한 기한은 바꾸지 않습니다.</p>
            <div className="form-actions"><Button type="submit" variant="primary" disabled={!!err} loading={save.isPending}>조치 기한 저장</Button></div>
          </form>
        </Panel>
      )}
    </>
  );
}
