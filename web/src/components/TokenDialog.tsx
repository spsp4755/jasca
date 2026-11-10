import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type ApiError } from "../api/client";
import type { TokenCreate, TokenCreated, TokenScope } from "../api/types";
import { copyText } from "../lib/clipboard";
import { dateInput, endOfDayISO, fmtDate } from "../lib/format";
import Button from "./Button";
import Dialog from "./Dialog";
import Field from "./Field";
import Icon from "./Icon";
import { useToast } from "./Toast";

const SCOPES: [TokenScope, string, string][] = [
  ["upload", "업로드", "CI에서 스캔 결과를 올립니다."],
  ["read", "읽기", "이 프로젝트의 결과, 대상, 정책 등을 조회합니다."],
];

/** Create an API token. The plaintext is shown exactly once, here, with a copy button. */
export default function TokenDialog({ open, onClose, projectKey }: { open: boolean; onClose: () => void; projectKey: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<TokenScope[]>(["upload"]);
  const [expires, setExpires] = useState(dateInput(90));
  const [touched, setTouched] = useState(false);
  const create = useMutation<TokenCreated, ApiError, TokenCreate>({
    mutationFn: (b) => api.post<TokenCreated>(`/projects/${projectKey}/tokens`, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: [`/projects/${projectKey}/tokens`] }),
  });
  const close = () => { onClose(); create.reset(); setName(""); setScopes(["upload"]); setExpires(dateInput(90)); setTouched(false); };
  const nameErr = touched && !name.trim() ? "이름을 입력하세요. 예: gitlab-ci" : name.length > 100 ? "100자 이하로 입력하세요." : undefined;
  const dateErr = !expires || expires < dateInput(1) || expires > dateInput(364) ? "내일부터 1년 안의 날짜를 고르세요." : undefined;
  const scopeErr = scopes.length ? undefined : "권한을 하나 이상 고르세요.";
  const submit = () => {
    setTouched(true);
    if (!name.trim() || nameErr || dateErr || scopeErr) return;
    create.mutate({ name: name.trim(), scopes, expires_at: endOfDayISO(expires) });
  };
  const token = create.data?.token;

  if (token) {
    return (
      <Dialog open={open} onClose={close} title="토큰을 만들었습니다" size="md" dismissable={false}
        footer={<Button variant="primary" onClick={close}>복사했습니다, 닫기</Button>}>
        <div className="alert alert-warn" role="alert" style={{ margin: 0 }}>
          <Icon name="alert" />이 토큰은 지금 한 번만 보입니다. 창을 닫으면 다시 볼 수 없으니 CI 비밀 변수에 바로 저장하세요.
        </div>
        <div className="secret-box">
          <code className="mono">{token}</code>
          <Button size="sm" icon="copy" onClick={async () => toast((await copyText(token)) ? "토큰을 복사했습니다." : "복사하지 못했습니다. 직접 선택해 복사하세요.", "info")}>복사</Button>
        </div>
        <p className="muted" style={{ fontSize: 13 }}>{fmtDate(endOfDayISO(expires))}까지 쓸 수 있습니다. 유출되면 토큰 목록에서 바로 폐기하세요.</p>
      </Dialog>
    );
  }
  return (
    <Dialog open={open} onClose={close} title="API 토큰 만들기" description="CI나 스크립트가 이 프로젝트에 접근할 때 씁니다."
      footer={<><Button onClick={close}>취소</Button><Button variant="primary" loading={create.isPending} onClick={submit}>만들기</Button></>}>
      <form onSubmit={(e) => { e.preventDefault(); submit(); }} style={{ display: "contents" }}>
        <Field label="이름" required error={nameErr} hint={nameErr ? undefined : "어디에 쓰는 토큰인지 알 수 있게 짓습니다."}>
          <input className="input" value={name} maxLength={100} autoFocus onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} />
        </Field>
        <fieldset className="field">
          <legend className="field-label">권한</legend>
          <div className="choice-list">
            {SCOPES.map(([s, label, hint]) => (
              <label key={s} className="choice">
                <input type="checkbox" checked={scopes.includes(s)} onChange={(e) => setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))} />
                <span><b>{label}</b><span className="muted">{hint}</span></span>
              </label>
            ))}
          </div>
          {scopeErr && <p className="field-err" role="alert">{scopeErr}</p>}
        </fieldset>
        <Field label="만료일" required error={dateErr} hint={dateErr ? undefined : "최대 1년입니다. 그날 23:59에 만료됩니다."}>
          <input className="input" type="date" value={expires} min={dateInput(1)} max={dateInput(364)} onChange={(e) => setExpires(e.target.value)} />
        </Field>
        {create.isError && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" />{create.error.message}</div>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
