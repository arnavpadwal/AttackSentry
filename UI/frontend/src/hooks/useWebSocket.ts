import { useEffect, useRef, useCallback } from 'react';
import { useAuthStore } from '@/stores';
import { WS_BASE } from '@/config/api';

interface UseWebSocketOptions<T> {
  path: string;
  parse: (raw: string) => T;
  onFlush: (messages: T[]) => void;
  enabled?: boolean;
  maxBufferSize?: number;
}

export function useWebSocket<T>({
  path,
  parse,
  onFlush,
  enabled = true,
  maxBufferSize = 500,
}: UseWebSocketOptions<T>) {
  const wsRef = useRef<WebSocket | null>(null);
  const bufferRef = useRef<T[]>([]);
  const rafRef = useRef<number | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptRef = useRef(0);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  const onFlushRef = useRef(onFlush);
  onFlushRef.current = onFlush;

  const parseRef = useRef(parse);
  parseRef.current = parse;

  // RAF flush loop
  const flush = useCallback(() => {
    if (bufferRef.current.length > 0) {
      const batch = bufferRef.current;
      bufferRef.current = [];
      onFlushRef.current(batch);
    }
    rafRef.current = requestAnimationFrame(flush);
  }, []);

  useEffect(() => {
    if (!enabled || !isAuthenticated) return;

    const connect = () => {
      const url = `${WS_BASE}${path}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log(`[WS] Connected: ${path}`);
        reconnectAttemptRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const parsed = parseRef.current(event.data);
          bufferRef.current.push(parsed);

          if (bufferRef.current.length >= maxBufferSize) {
            const batch = bufferRef.current;
            bufferRef.current = [];
            onFlushRef.current(batch);
          }
        } catch (err) {
          console.warn(`[WS] Parse error on ${path}:`, err);
        }
      };

      ws.onclose = (event) => {
        console.log(`[WS] Closed: ${path}`, event.code);
        if (!event.wasClean) scheduleReconnect();
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    const scheduleReconnect = () => {
      const attempt = reconnectAttemptRef.current;
      const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
      reconnectTimeoutRef.current = setTimeout(() => {
        reconnectAttemptRef.current += 1;
        connect();
      }, delay);
    };

    connect();
    rafRef.current = requestAnimationFrame(flush);

    return () => {
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmount');
        wsRef.current = null;
      }
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      bufferRef.current = [];
    };
  }, [path, enabled, isAuthenticated, maxBufferSize, flush]);

  const send = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  return { send };
}
