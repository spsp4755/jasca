import { useLayoutEffect, useRef, useState, type CSSProperties, type Key, type ReactNode } from "react";

export type Column<T> = {
  key: string;
  header: ReactNode;
  /** Cell content; defaults to String(row[key]). */
  render?: (row: T) => ReactNode;
  width?: number | string;
  align?: "left" | "right" | "center";
  /** Monospace cell (IDs, versions, digests). */
  mono?: boolean;
  /** Keep on one line; with a width it is also cut with an ellipsis (without one the column grows to fit). */
  nowrap?: boolean;
  /** Class for the column's header and cells (e.g. "col-wide": hidden on narrow screens). */
  className?: string;
};

export type TableProps<T> = {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => Key;
  /** Makes rows clickable and keyboard-activatable (Enter). Links inside cells still work on their own. */
  onRowClick?: (row: T) => void;
  /** Shown instead of the body when rows is empty (use <Empty compact />). */
  empty?: ReactNode;
  loading?: boolean;
  /** Visually hidden caption for screen readers. */
  caption?: string;
  /** Checkbox column. Pass the selected keys and a setter. */
  selected?: Set<Key>;
  onSelectedChange?: (next: Set<Key>) => void;
  /** With the checkbox column: rows that cannot be chosen get a disabled checkbox and stay out of "모두 선택". */
  selectableRow?: (row: T) => boolean;
  /**
   * Makes the table its own scroll box (e.g. "calc(100vh - 260px)").
   * Without it the header sticks to the top of the page scroll area.
   */
  maxHeight?: number | string;
  dense?: boolean;
};

export default function Table<T>({ columns, rows, rowKey, onRowClick, empty, loading, caption, selected, onSelectedChange, selectableRow, maxHeight, dense }: TableProps<T>) {
  const selectable = !!selected && !!onSelectedChange;
  const keys = rows.map(rowKey);
  const pickable = selectableRow ? keys.filter((_, i) => selectableRow(rows[i])) : keys; // what "모두 선택" toggles
  const all = selectable && pickable.length > 0 && pickable.every((k) => selected!.has(k));
  const some = selectable && !all && pickable.some((k) => selected!.has(k));
  // A table wider than its box scrolls sideways instead of being cut off. Only then: a scrolling box takes the
  // sticky header away from the page scroll, so tables that fit keep overflow-x: clip.
  const wrap = useRef<HTMLDivElement>(null);
  const [wide, setWide] = useState(false);
  useLayoutEffect(() => {
    const el = wrap.current, table = el?.firstElementChild;
    if (!el || !table) return;
    const ro = new ResizeObserver(() => setWide(table.scrollWidth > el.clientWidth + 1));
    ro.observe(el); ro.observe(table);
    return () => ro.disconnect();
  }, []);
  const toggle = (k: Key) => {
    const next = new Set(selected);
    if (next.has(k)) next.delete(k); else next.add(k);
    onSelectedChange!(next);
  };
  const span = columns.length + (selectable ? 1 : 0);
  const wrapStyle: CSSProperties | undefined = maxHeight !== undefined ? { maxHeight, overflow: "auto" } : undefined;
  return (
    <div ref={wrap} className={`table-wrap${maxHeight !== undefined ? " table-scroll" : ""}${wide ? " table-wide" : ""}`} style={wrapStyle} tabIndex={wide ? 0 : undefined}>
      <table className={`table${dense ? " table-dense" : ""}`} aria-busy={loading || undefined}>
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {selectable && (
              <th className="col-check">
                <input type="checkbox" aria-label="모두 선택" checked={all} disabled={pickable.length === 0} ref={(el) => { if (el) el.indeterminate = some; }}
                  onChange={() => onSelectedChange!(all ? new Set([...selected!].filter((k) => !keys.includes(k))) : new Set([...selected!, ...pickable]))} />
              </th>
            )}
            {columns.map((c) => (
              <th key={c.key} scope="col" className={c.className} style={{ width: c.width, textAlign: c.align }}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading && rows.length === 0 ? (
            Array.from({ length: 4 }, (_, i) => (
              <tr key={i} className="row-skeleton" aria-hidden="true">
                <td colSpan={span}><span className="skeleton" style={{ width: `${70 - i * 12}%` }} /></td>
              </tr>
            ))
          ) : rows.length === 0 ? (
            <tr className="row-empty"><td colSpan={span}>{empty ?? "항목이 없습니다."}</td></tr>
          ) : (
            rows.map((row, i) => {
              const k = keys[i];
              const isSel = selectable && selected!.has(k);
              return (
                <tr key={k} className={`${onRowClick ? "row-click" : ""}${isSel ? " row-selected" : ""}`}
                  tabIndex={onRowClick ? 0 : undefined}
                  onClick={onRowClick ? (e) => { if (!(e.target as HTMLElement).closest("a,button,input,label,select,textarea")) onRowClick(row); } : undefined}
                  onKeyDown={onRowClick ? (e) => { if (e.key === "Enter" && e.target === e.currentTarget) onRowClick(row); } : undefined}>
                  {selectable && (
                    <td className="col-check"><input type="checkbox" aria-label="선택" checked={isSel} disabled={!!selectableRow && !selectableRow(row)} onChange={() => toggle(k)} /></td>
                  )}
                  {columns.map((c) => (
                    <td key={c.key} style={{ textAlign: c.align }} className={[c.mono && "mono", c.nowrap && "nowrap", c.nowrap && c.width !== undefined && "truncate", c.className].filter(Boolean).join(" ") || undefined}>
                      {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? "")}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
