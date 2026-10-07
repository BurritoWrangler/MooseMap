import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

/**
 * A global polite ARIA live region. Call `announce(message)` to have screen
 * readers read status updates (e.g. "Port scan complete") without stealing
 * focus. One shared region avoids the common bug of multiple competing regions.
 */
interface AnnouncerApi {
  announce: (message: string) => void;
}

const AnnouncerContext = createContext<AnnouncerApi | null>(null);

export function AnnouncerProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState("");
  const clearTimer = useRef<number | undefined>(undefined);

  const announce = useCallback((msg: string) => {
    // Toggle to empty first so repeated identical messages are re-announced.
    setMessage("");
    window.requestAnimationFrame(() => setMessage(msg));
    if (clearTimer.current) window.clearTimeout(clearTimer.current);
    clearTimer.current = window.setTimeout(() => setMessage(""), 5000);
  }, []);

  const api = useMemo(() => ({ announce }), [announce]);

  return (
    <AnnouncerContext.Provider value={api}>
      {children}
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="visually-hidden"
      >
        {message}
      </div>
    </AnnouncerContext.Provider>
  );
}

export function useAnnouncer(): AnnouncerApi {
  const ctx = useContext(AnnouncerContext);
  if (!ctx) throw new Error("useAnnouncer must be used within AnnouncerProvider");
  return ctx;
}
