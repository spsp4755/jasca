import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { useToast } from "../../components/Toast";
import type { AIPrompts, AISettings, AISettingsPut } from "../../api/types";
import { Check, Loading, Panel, SecretField, useSave } from "./parts";

export default function AI() {
  const q = useApi<AISettings>("/admin/ai");
  const pq = useApi<AIPrompts>("/admin/ai/prompts");
  const toast = useToast();
  const [f, setF] = useState<AISettingsPut>({ base_url: "", model: "", timeout_sec: 120, max_input_tokens: 24000, enabled: false });
  const [key, setKey] = useState("");
  const [pr, setPr] = useState<AIPrompts>({ vuln_guide: "", project_report: "" });
  useEffect(() => { if (q.data) { const { api_key_set: _k, ...rest } = q.data; setF(rest); setKey(""); } }, [q.data]);
  useEffect(() => { if (pq.data) setPr(pq.data); }, [pq.data]);
  const body = () => ({ ...f, ...(key ? { api_key: key } : {}) });
  const save = useSave(() => api.put("/admin/ai", body()), { ok: "AI 설정을 저장했습니다.", invalidate: ["/admin/ai"] });
  const test = useSave(() => api.post<{ ok?: boolean; error?: string; message?: string }>("/admin/ai/test", body()), {
    onDone: (r) => (r?.error ? toast(`연결 실패: ${r.error}`, "error") : toast("연결했습니다.", "ok")),
  });
  const savePr = useSave(() => api.put("/admin/ai/prompts", pr), { ok: "프롬프트를 저장했습니다.", invalidate: ["/admin/ai/prompts"] });
  const num = (k: "timeout_sec" | "max_input_tokens") => (e: { target: { value: string } }) => setF({ ...f, [k]: Number(e.target.value) });
  return (
    <>
      <PageHeader title="AI" description="사내 LLM(OpenAI 호환 API)으로 취약점 조치 가이드와 프로젝트 보고서를 만듭니다. 외부로 나가는 요청은 없습니다." />
      <Loading q={q} />
      {q.data && (
        <Panel title="연결 설정">
          <form className="admin-form" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
            <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>AI 기능 사용</Check>
            <Field label="Base URL" hint="예: http://llm.internal:8000/v1" required><input className="input" value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} /></Field>
            <Field label="모델 이름" required><input className="input" value={f.model} onChange={(e) => setF({ ...f, model: e.target.value })} /></Field>
            <SecretField label="API 키" isSet={q.data.api_key_set} value={key} onChange={setKey} hint={q.data.api_key_set ? undefined : "키가 필요 없는 서버면 비워 두세요."} />
            <div className="two">
              <Field label="응답 대기 시간 (초)"><input className="input" type="number" min={1} value={f.timeout_sec} onChange={num("timeout_sec")} /></Field>
              <Field label="최대 입력 토큰" hint="이보다 길면 취약점 목록을 줄여 보냅니다."><input className="input" type="number" min={1} value={f.max_input_tokens} onChange={num("max_input_tokens")} /></Field>
            </div>
            <div className="admin-actions">
              <Button type="submit" variant="primary" loading={save.isPending}>저장</Button>
              <Button loading={test.isPending} onClick={() => test.mutate(undefined)}>연결 시험</Button>
            </div>
          </form>
        </Panel>
      )}
      <Panel title="프롬프트">
        <Loading q={pq} />
        {pq.data && (
          <form className="admin-form" style={{ maxWidth: 760 }} onSubmit={(e) => { e.preventDefault(); savePr.mutate(undefined); }}>
            <Field label="취약점 조치 가이드"><textarea className="input" rows={6} value={pr.vuln_guide} onChange={(e) => setPr({ ...pr, vuln_guide: e.target.value })} /></Field>
            <Field label="프로젝트 보고서"><textarea className="input" rows={6} value={pr.project_report} onChange={(e) => setPr({ ...pr, project_report: e.target.value })} /></Field>
            <div className="admin-actions"><Button type="submit" variant="primary" loading={savePr.isPending}>프롬프트 저장</Button></div>
          </form>
        )}
      </Panel>
    </>
  );
}
