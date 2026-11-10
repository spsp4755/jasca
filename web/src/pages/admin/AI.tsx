import { useEffect, useState } from "react";
import PageHeader from "../../components/PageHeader";
import Field from "../../components/Field";
import Button from "../../components/Button";
import { useApi } from "../../api/hooks";
import { api } from "../../api/client";
import { useToast } from "../../components/Toast";
import type { AIPrompts, AIPromptsView, AISettings, AISettingsPut } from "../../api/types";
import { Check, Loading, Panel, SecretField, useSave } from "./parts";

export default function AI() {
  const q = useApi<AISettings>("/admin/ai");
  const pq = useApi<AIPromptsView>("/admin/ai/prompts");
  const toast = useToast();
  const [f, setF] = useState<AISettingsPut>({ base_url: "", model: "", timeout_sec: 120, max_input_tokens: 12000, enabled: false });
  const [key, setKey] = useState("");
  const [pr, setPr] = useState<AIPrompts>({ vuln_guide: "", project_report: "" });
  useEffect(() => { if (q.data) { const { api_key_set: _k, ...rest } = q.data; setF(rest); setKey(""); } }, [q.data]);
  useEffect(() => { if (pq.data) setPr({ vuln_guide: pq.data.vuln_guide, project_report: pq.data.project_report }); }, [pq.data]);
  const body = () => ({ ...f, ...(key ? { api_key: key } : {}) });
  const save = useSave(() => api.put("/admin/ai", body()), { ok: "AI 설정을 저장했습니다.", invalidate: ["/admin/ai", "/auth/config"] }); // /auth/config tells the screens whether to offer AI
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
              <Field label="응답 대기 시간 (초)"><input className="input" type="number" min={1} max={600} value={f.timeout_sec} onChange={num("timeout_sec")} /></Field>
              <Field label="최대 입력 토큰" hint="100 이상. 이보다 길면 취약점 목록을 줄여 보냅니다. 기본 12000."><input className="input" type="number" min={100} value={f.max_input_tokens} onChange={num("max_input_tokens")} /></Field>
            </div>
            <div className="admin-actions">
              <Button type="submit" variant="primary" loading={save.isPending}>저장</Button>
              <Button loading={test.isPending} onClick={() => test.mutate(undefined)}>연결 시험</Button>
            </div>
            <p className="muted" style={{ margin: 0 }}>저장된 API 키는 저장된 Base URL로만 보냅니다. 다른 주소로 시험하려면 키를 다시 입력하세요.</p>
          </form>
        </Panel>
      )}
      <Panel title="프롬프트">
        <Loading q={pq} />
        {pq.data && (
          <form className="admin-form" style={{ maxWidth: 760 }} onSubmit={(e) => { e.preventDefault(); savePr.mutate(undefined); }}>
            <p className="muted" style={{ margin: 0 }}>비워 두면 기본 프롬프트를 씁니다. 그대로 써도 됩니다. 말투나 항목을 바꾸고 싶을 때만 기본 프롬프트를 불러와 고치세요.</p>
            {([["vuln_guide", "취약점 조치 가이드", "요청이 \"[파트 1: 일반 설명]\"과 \"[파트 2: 내 영향]\" 두 가지로 옵니다. 고칠 때 두 파트 설명은 남겨 두세요."],
              ["project_report", "프로젝트 보고서", "프로젝트의 열린 결과, 추세, 예외 현황이 입력으로 갑니다."]] as const).map(([k, label, hint]) => (
              <div key={k}>
                <Field label={label} hint={`${pr[k] ? "직접 쓴 프롬프트를 씁니다." : "비어 있음: 기본 프롬프트를 씁니다."} ${hint}`}>
                  <textarea className="input" rows={8} placeholder={pq.data.defaults[k]} value={pr[k]} onChange={(e) => setPr({ ...pr, [k]: e.target.value })} />
                </Field>
                <div className="admin-actions" style={{ marginTop: 6 }}>
                  <Button type="button" size="sm" disabled={pr[k] === pq.data.defaults[k]} onClick={() => setPr({ ...pr, [k]: pq.data.defaults[k] })}>기본 프롬프트 불러오기</Button>
                  <Button type="button" size="sm" disabled={!pr[k]} onClick={() => setPr({ ...pr, [k]: "" })}>비우기</Button>
                </div>
              </div>
            ))}
            <div className="admin-actions"><Button type="submit" variant="primary" loading={savePr.isPending}>프롬프트 저장</Button></div>
          </form>
        )}
      </Panel>
    </>
  );
}
