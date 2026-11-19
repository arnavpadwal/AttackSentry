import { useCallback } from 'react';
import { useWebSocket } from './useWebSocket';
import { useAlertStreamStore } from '@/stores';
import type { Alert } from '@/types';

export function useAlertStream() {
  const appendAlert = useAlertStreamStore((s) => s.appendAlert);

  const parse = useCallback((raw: string): Alert => JSON.parse(raw) as Alert, []);

  const onFlush = useCallback(
    (alerts: Alert[]) => {
      alerts.forEach((alert) => appendAlert(alert));
    },
    [appendAlert]
  );

  return useWebSocket<Alert>({
    path: '/ws/alerts',
    parse,
    onFlush,
    maxBufferSize: 50,
  });
}
