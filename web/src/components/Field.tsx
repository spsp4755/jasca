import { cloneElement, isValidElement, useId, type ReactElement, type ReactNode } from "react";

/**
 * Label + one control + hint/error. The child (an <input className="input">, <select className="input">,
 * <textarea className="input">…) receives id, aria-describedby and aria-invalid.
 */
export default function Field({ label, hint, error, required, children, className }: {
  label: ReactNode; hint?: ReactNode; error?: ReactNode; required?: boolean; children: ReactElement; className?: string;
}) {
  const id = useId();
  const described = [hint && `${id}-h`, error && `${id}-e`].filter(Boolean).join(" ") || undefined;
  const control = isValidElement(children)
    ? cloneElement(children as ReactElement<Record<string, unknown>>, { id, "aria-describedby": described, "aria-invalid": error ? true : undefined, required })
    : children;
  return (
    <div className={`field${error ? " field-error" : ""}${className ? ` ${className}` : ""}`}>
      <label htmlFor={id} className="field-label">{label}{required && <span className="field-req" aria-hidden="true"> *</span>}</label>
      {control}
      {hint && <p id={`${id}-h`} className="field-hint">{hint}</p>}
      {error && <p id={`${id}-e`} className="field-err" role="alert">{error}</p>}
    </div>
  );
}
