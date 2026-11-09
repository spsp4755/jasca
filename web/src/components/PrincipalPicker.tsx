import { useEffect, useId, useState } from "react";
import { useApi } from "../api/hooks";
import type { Principal } from "../api/types";

const keyOf = (p: { kind?: string; principal_kind?: string; principal: string }) => `${p.kind ?? p.principal_kind}:${p.principal}`;

/** Combobox over GET /principals?q= (users, groups and departments). `taken` holds "kind:principal" keys to hide. */
export default function PrincipalPicker({ onPick, taken, label = "사용자나 그룹 추가" }: {
  onPick: (p: Principal) => void; taken?: Set<string>; label?: string;
}) {
  const id = useId();
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  useEffect(() => { const t = setTimeout(() => setQ(text.trim()), 220); return () => clearTimeout(t); }, [text]);
  const res = useApi<Principal[] | null>(q ? `/principals?q=${encodeURIComponent(q)}` : null, { staleTime: 60_000 });
  const items = (res.data ?? []).filter((p) => !taken?.has(keyOf(p)));
  const show = open && !!q;
  const pick = (p: Principal) => { onPick(p); setText(""); setQ(""); setActive(0); };
  return (
    <div className="picker">
      <label htmlFor={`${id}-i`} className="sr-only">{label}</label>
      <input id={`${id}-i`} className="input" role="combobox" aria-expanded={show} aria-controls={`${id}-l`} aria-autocomplete="list"
        aria-activedescendant={show && items[active] ? `${id}-o${active}` : undefined}
        placeholder="이름, 아이디, 이메일 또는 /그룹 경로로 찾기" value={text} autoComplete="off"
        onChange={(e) => { setText(e.target.value); setOpen(true); setActive(0); }}
        onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 120)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, items.length - 1)); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
          else if (e.key === "Enter" && show && items[active]) { e.preventDefault(); pick(items[active]); }
          else if (e.key === "Escape" && show) { e.stopPropagation(); setOpen(false); }
        }} />
      {show && (
        <ul id={`${id}-l`} role="listbox" className="picker-list" aria-label="검색 결과">
          {res.isFetching && !items.length ? <li className="picker-note">찾는 중…</li>
            : res.isError ? <li className="picker-note">{res.error.message}</li>
            : !items.length ? <li className="picker-note">일치하는 사용자나 그룹이 없습니다.</li>
            : items.map((p, i) => (
              <li key={keyOf(p)} id={`${id}-o${i}`} role="option" aria-selected={i === active}
                className="picker-opt" onMouseDown={(e) => e.preventDefault()} onMouseEnter={() => setActive(i)} onClick={() => pick(p)}>
                <span className={`tag ${p.kind === "user" ? "tag-quiet" : ""}`}>{p.kind === "user" ? "사용자" : "그룹"}</span>
                <span className={p.kind === "group" ? "mono" : undefined}>{p.display}</span>
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}

export { keyOf as principalKey };
