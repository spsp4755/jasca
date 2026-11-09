import { useRef, type KeyboardEvent } from "react";

export type TabItem = { id: string; label: string; count?: number; hidden?: boolean };

/**
 * Tab list only; the caller renders the panel for `value` (wrap it in role="tabpanel" with
 * id={`tabpanel-${value}`} and aria-labelledby={`tab-${value}`} when you want the full ARIA pairing).
 * Arrow keys, Home and End move between tabs.
 */
export default function Tabs({ tabs, value, onChange, label }: {
  tabs: TabItem[]; value: string; onChange: (id: string) => void; label?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const shown = tabs.filter((t) => !t.hidden);
  const onKey = (e: KeyboardEvent) => {
    const i = shown.findIndex((t) => t.id === value);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: shown.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const t = shown[(next + shown.length) % shown.length];
    onChange(t.id);
    ref.current?.querySelector<HTMLButtonElement>(`[data-tab="${CSS.escape(t.id)}"]`)?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} ref={ref} onKeyDown={onKey}>
      {shown.map((t) => (
        <button key={t.id} type="button" role="tab" id={`tab-${t.id}`} data-tab={t.id} aria-selected={t.id === value}
          aria-controls={`tabpanel-${t.id}`} tabIndex={t.id === value ? 0 : -1} className="tab" onClick={() => onChange(t.id)}>
          {t.label}
          {t.count !== undefined && <span className="tab-count">{t.count.toLocaleString("ko-KR")}</span>}
        </button>
      ))}
    </div>
  );
}
