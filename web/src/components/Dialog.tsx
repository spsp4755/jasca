import { useEffect, useId, useRef, type ReactNode } from "react";
import Icon from "./Icon";

/**
 * Modal on the native <dialog>: focus is trapped and Esc closes it (cancel -> onClose). It opens with focus on the
 * first control of the body, else on the first footer button (the safe one: 취소 comes first), else on the dialog
 * itself (always for a drawer, which is for reading). Closing returns focus to the opener.
 * A click on the backdrop closes it too. Put the buttons in `footer`. `dismissable={false}` keeps it open on Esc and
 * backdrop clicks (for content that is lost on close, like a new token); the buttons still close it.
 */
export default function Dialog({ open, onClose, title, description, children, footer, size = "md", dismissable = true }: {
  open: boolean; onClose: () => void; title: ReactNode; description?: ReactNode; children?: ReactNode; footer?: ReactNode; dismissable?: boolean;
  size?: "sm" | "md" | "lg" | "drawer"; // drawer: full-height panel on the right
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  // showModal() alone focuses the close (X) button, so an Enter right after opening would close the dialog
  const focusFirst = (d: HTMLDialogElement) => {
    const first = (sel: string) => d.querySelector<HTMLElement>(`${sel}:not(:disabled, [hidden], [type=hidden])`);
    // a drawer is opened with Enter on a table row: a control focused there (assign to me) would be hit by the next Enter
    ((size === "drawer" ? null : first(".dialog-body :is(input, select, textarea, button)") ?? first(".dialog-foot button")) ?? d).focus();
  };
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) { d.showModal(); focusFirst(d); }
    else if (!open && d.open) d.close();
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps
  // the content changed under the focus (a form replaced by its result): start again instead of leaving focus nowhere
  useEffect(() => {
    const d = ref.current;
    if (d?.open && !d.contains(document.activeElement)) focusFirst(d);
  });
  return (
    <dialog ref={ref} tabIndex={-1} className={`dialog dialog-${size}`} aria-labelledby={`${id}-t`} aria-describedby={description ? `${id}-d` : undefined}
      aria-modal={open ? "true" : undefined}
      onCancel={(e) => { e.preventDefault(); if (dismissable) onClose(); }}
      onMouseDown={(e) => { if (dismissable && e.target === e.currentTarget) onClose(); }}>
      {open && (
        <div className="dialog-inner">
          <header className="dialog-head">
            <div>
              <h2 id={`${id}-t`}>{title}</h2>
              {description && <p id={`${id}-d`} className="dialog-desc">{description}</p>}
            </div>
            <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={onClose} aria-label="닫기"><Icon name="x" /></button>
          </header>
          {children && <div className="dialog-body">{children}</div>}
          {footer && <footer className="dialog-foot">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}
