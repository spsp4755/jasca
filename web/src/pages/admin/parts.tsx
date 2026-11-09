import { useState, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import Button from "../../components/Button";
import Field from "../../components/Field";
import { useToast } from "../../components/Toast";
import type { ApiError } from "../../api/client";

/** Secret input: "설정됨 + 바꾸기" when stored, never prefilled. `value` is "" until the user types a new one. */
export function SecretField({ label, isSet, value, onChange, hint }: {
  label: string; isSet: boolean; value: string; onChange: (v: string) => void; hint?: ReactNode;
}) {
  const [editing, setEditing] = useState(false);
  if (isSet && !editing) {
    return (
      <div className="field">
        <span className="field-label">{label}</span>
        <div className="secret-set"><span className="tag">설정됨</span><Button size="sm" onClick={() => setEditing(true)}>바꾸기</Button></div>
        {hint && <p className="field-hint">{hint}</p>}
      </div>
    );
  }
  return (
    <Field label={label} hint={hint ?? (isSet ? "비워 두면 기존 값을 유지합니다." : undefined)}>
      <input className="input" type="password" autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}

/** Mutation that toasts success/failure and invalidates the given GET paths. */
export function useSave<V, R = unknown>(fn: (v: V) => Promise<R>, opts: { ok?: string; invalidate?: string[]; onDone?: (r: R) => void } = {}) {
  const qc = useQueryClient();
  const toast = useToast();
  return useMutation<R, ApiError, V>({
    mutationFn: fn,
    onSuccess: (r) => {
      if (opts.ok) toast(opts.ok, "ok");
      opts.invalidate?.forEach((p) => qc.invalidateQueries({ queryKey: [p] }));
      opts.onDone?.(r);
    },
    onError: (e) => toast(e.message, "error"),
  });
}

export function Check({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return <label className="check-row"><input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />{children}</label>;
}

export function Panel({ title, meta, children }: { title: string; meta?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-head"><h2>{title}</h2>{meta && <span className="panel-meta">{meta}</span>}</div>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function Loading({ q }: { q: { isLoading: boolean; error: ApiError | null } }) {
  if (q.error) return <div className="alert alert-danger" role="alert">{q.error.message}</div>;
  return q.isLoading ? <div className="skeleton" style={{ height: 120 }} /> : null;
}
