import { useCallback, useEffect } from 'react';
import { useWebSocket } from './useWebSocket';
import { useTelemetryStore } from '@/stores';
import type { Flow } from '@/types';
import { api } from '@/lib/axios';
import { useAuthStore } from '@/stores';

export function useTelemetry() {
  const appendFlows = useTelemetryStore((s) => s.appendFlows);
  const authenticated = useAuthStore((s) => s.isAuthenticated);

  useEffect(() => {
    if (!authenticated) return;
    api.get<Flow[]>('/api/traffic/recent', { params: { limit: 200 } })
      .then(({ data }) => { if (data.length) appendFlows(data); })
      .catch(() => undefined);
  }, [authenticated, appendFlows]);

  const parse = useCallback((raw: string): Flow => JSON.parse(raw) as Flow, []);

  const onFlush = useCallback(
    (flows: Flow[]) => {
      appendFlows(flows);
    },
    [appendFlows]
  );

  return useWebSocket<Flow>({
    path: '/ws/telemetry',
    parse,
    onFlush,
    maxBufferSize: 200,
  });
}
