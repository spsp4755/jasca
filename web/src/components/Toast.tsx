import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import Icon from "./Icon";

export type ToastTone = "info" | "ok" | "error";
type Item = { id: number; message: string; tone: ToastTone };
type Show = (message: string, tone?: ToastTone) => void;

const Ctx = createContext<Show>(() => {});

/** `const toast = useToast(); toast("저장했습니다.", "ok")`. Errors stay 8s, others 4s. */
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Item[]>([]);
  const seq = useRef(0);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const show = useCallback<Show>((message, tone = "info") => {
    const id = ++seq.current;
    setItems((xs) => [...xs.slice(-3), { id, message, tone }]);
    setTimeout(() => dismiss(id), tone === "error" ? 8000 : 4000);
  }, [dismiss]);
  return (
    <Ctx.Provider value={show}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>
            <Icon name={t.tone === "ok" ? "check" : t.tone === "error" ? "alert" : "info"} />
            <span>{t.message}</span>
            <button type="button" className="toast-x" onClick={() => dismiss(t.id)} aria-label="알림 닫기"><Icon name="x" size={14} /></button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
