import { useEffect, useRef } from "react";

// Global shortcuts. Sequences are space separated ("g h") and must finish within SEQ_MS.
// ShortcutHelp renders SHORTCUTS, so the help table and the keymap cannot drift apart.
export const SHORTCUTS: { keys: string; label: string }[] = [
  { keys: "/", label: "검색으로 이동" },
  { keys: "g h", label: "홈" },
  { keys: "g p", label: "프로젝트" },
  { keys: "g f", label: "취약점" },
  { keys: "g s", label: "스캔하기" },
  { keys: "?", label: "단축키 도움말" },
  { keys: "escape", label: "대화상자 닫기 · 검색 나가기" },
];

export const SEQ_MS = 1000;

const CAPS: Record<string, string> = { escape: "Esc", enter: "Enter" };
/** "g h" -> ["G", "H"] for keycaps. */
export const keyCaps = (combo: string) => combo.split(" ").map((k) => CAPS[k] || k.toUpperCase());

// Letters come from e.code so a Korean layout ("ㅎ" for KeyG) still matches; punctuation from e.key ("?" is already shifted).
function comboOf(e: KeyboardEvent): string | null {
  if (e.ctrlKey || e.metaKey || e.altKey) return null;
  if (/^Key[A-Z]$/.test(e.code)) return e.code.slice(3).toLowerCase();
  const key = (e.key || "").toLowerCase();
  return !key || ["shift", "control", "alt", "meta", "capslock", "process"].includes(key) ? null : key;
}

export function isEditable(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  if (!el || !el.tagName) return false;
  return ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName) || el.isContentEditable;
}

export type SeqState = { prefix: string; at: number } | undefined;

/** Pure matcher: returns the bound value (or null) and the next sequence state. */
export function matchSequence<V>(state: SeqState, e: KeyboardEvent, now: number, map: Record<string, V>, modal = false): { action: V | null; state: SeqState } {
  if (e.isComposing || e.keyCode === 229) return { action: null, state };
  const combo = comboOf(e);
  if (!combo) return { action: null, state };
  // typing and open dialogs own plain keys; Esc is handled by the field or the dialog itself
  if (isEditable(e.target) || modal) return { action: null, state: undefined };
  if (state && now - state.at <= SEQ_MS) {
    const seq = `${state.prefix} ${combo}`;
    if (seq in map) return { action: map[seq], state: undefined };
  }
  if (Object.keys(map).some((k) => k.startsWith(combo + " "))) return { action: null, state: { prefix: combo, at: now } };
  return { action: combo in map ? map[combo] : null, state: undefined };
}

/** map: combo -> handler. Listens on window for the component's lifetime. */
export function useHotkeys(map: Record<string, (e: KeyboardEvent) => void>) {
  const ref = useRef(map);
  ref.current = map;
  useEffect(() => {
    let state: SeqState;
    const on = (e: KeyboardEvent) => {
      if (e.defaultPrevented) return;
      const r = matchSequence(state, e, Date.now(), ref.current, !!document.querySelector('[aria-modal="true"]'));
      state = r.state;
      if (r.action) { e.preventDefault(); r.action(e); }
    };
    addEventListener("keydown", on);
    return () => removeEventListener("keydown", on);
  }, []);
}
