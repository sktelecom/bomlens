/**
 * Minimal toast — no dependency, no portal library. A polite live region at the
 * bottom of the viewport announces transient feedback (link copied, download
 * started) and auto-dismisses. Wrap the app in <ToastProvider> and call
 * useToast().toast(message) from anywhere beneath it.
 */
import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from "react";

interface ToastItem {
  id: number;
  message: string;
}

interface ToastApi {
  toast: (message: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const DISMISS_MS = 2600;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);

  const toast = useCallback((message: string) => {
    const id = (seq.current += 1);
    setItems((prev) => [...prev, { id, message }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, DISMISS_MS);
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div
        className="pointer-events-none fixed inset-x-0 bottom-4 z-[60] flex flex-col items-center gap-2 px-4"
        aria-live="polite"
        aria-atomic="true"
      >
        {items.map((t) => (
          <div
            key={t.id}
            className="pointer-events-auto rounded-md border bg-card px-3 py-2 text-sm shadow-lg animate-fade-in"
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within a ToastProvider");
  return ctx;
}
