import { useQuery } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import { useSentryStatusStore } from '@/stores';
import type { SentryStatus, TrafficSummary } from '@/types';

export function useSentryStatus() {
  const setStatus = useSentryStatusStore((s) => s.setStatus);

  return useQuery({
    queryKey: queryKeys.sentry.status,
    queryFn: async (): Promise<SentryStatus> => {
      const { data } = await api.get('/api/sentry/status');
      setStatus({
        mode: data.mode,
        baselineProgress: data.baseline_progress_pct,
        uptime: data.uptime_seconds,
        activeHosts: data.active_hosts,
        modelVersions: data.model_versions,
      });
      return data;
    },
    refetchInterval: 5_000,
    staleTime: 0,
  });
}

export function useTrafficSummary(range: string) {
  return useQuery({
    queryKey: queryKeys.traffic.summary(range),
    queryFn: async (): Promise<TrafficSummary> => {
      const { data } = await api.get(`/api/traffic/summary?range=${range}`);
      return data;
    },
    refetchInterval: 10_000,
    staleTime: 5_000,
  });
}
