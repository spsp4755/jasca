import { useEffect, useId, useRef, type ReactNode } from "react";
import Icon from "./Icon";

/**
 * Modal on the native <dialog>: focus is trapped and Esc closes it (cancel -> onClose).
 * A click on the backdrop closes it too. Put the buttons in `footer`. `dismissable={false}` keeps it open on Esc and
 * backdrop clicks (for content that is lost on close, like a new token); the buttons still close it.
 */
export default function Dialog({ open, onClose, title, description, children, footer, size = "md", dismissable = true }: {
  open: boolean; onClose: () => void; title: ReactNode; description?: ReactNode; children?: ReactNode; footer?: ReactNode; dismissable?: boolean;
  size?: "sm" | "md" | "lg" | "drawer"; // drawer: full-height panel on the right
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    else if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} className={`dialog dialog-${size}`} aria-labelledby={`${id}-t`} aria-describedby={description ? `${id}-d` : undefined}
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
