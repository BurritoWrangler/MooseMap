import { useEffect, useRef, useState } from "react";
import type { EngineEvent } from "../api/types";

type ConnectionState = "connecting" | "open" | "closed";

interface EventStream {
  connection: ConnectionState;
  /** The most recent events, newest last, capped to `bufferSize`. */
  events: EngineEvent[];
  /** Monotonic counter so consumers can cheaply detect new events. */
  seq: number;
}

/**
 * Subscribe to the backend WebSocket event feed with automatic reconnection
 * (exponential backoff). Returns live connection state plus a rolling buffer of
 * decoded events. Honors the page lifecycle so we don't leak sockets.
 */
export function useEventStream(bufferSize = 500): EventStream {
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [events, setEvents] = useState<EngineEvent[]>([]);
  const [seq, setSeq] = useState(0);
  const retryRef = useRef(0);
  const closedByUs = useRef(false);

  useEffect(() => {
    closedByUs.current = false;
    let ws: WebSocket | null = null;
    let reconnectTimer: number | undefined;

    const url = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      return `${proto}://${location.host}/api/events`;
    };

    const connect = () => {
      setConnection("connecting");
      ws = new WebSocket(url());

      ws.onopen = () => {
        retryRef.current = 0;
        setConnection("open");
      };

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data) as EngineEvent;
          setEvents((prev) => {
            const next = [...prev, data];
            return next.length > bufferSize
              ? next.slice(next.length - bufferSize)
              : next;
          });
          setSeq((s) => s + 1);
        } catch {
          // ignore malformed frame
        }
      };

      ws.onclose = () => {
        setConnection("closed");
        if (closedByUs.current) return;
        // Exponential backoff capped at 10s.
        const delay = Math.min(1000 * 2 ** retryRef.current, 10_000);
        retryRef.current += 1;
        reconnectTimer = window.setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws?.close();
      };
    };

    connect();

    return () => {
      closedByUs.current = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [bufferSize]);

  return { connection, events, seq };
}
