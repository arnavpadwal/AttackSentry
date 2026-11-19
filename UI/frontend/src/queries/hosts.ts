import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import type { Alert, Host, HostDetail, TimeSeries } from '@/types';

export function useHosts() {
  return useQuery({
    queryKey: queryKeys.hosts.all,
    queryFn: async (): Promise<Host[]> => {
      const { data } = await api.get('/api/hosts');
      return data;
    },
    refetchInterval: 10_000,
    staleTime: 5_000,
  });
}

export function useHost(id: string) {
  return useQuery({
    queryKey: queryKeys.hosts.detail(id),
    queryFn: async (): Promise<HostDetail> => {
      const { data } = await api.get(`/api/hosts/${id}`);
      return data;
    },
    staleTime: 5_000,
  });
}

export function useHostTraffic(id: string, range: string) {
  return useQuery({
    queryKey: queryKeys.hosts.traffic(id, range),
    queryFn: async (): Promise<TimeSeries> => {
      const { data } = await api.get(`/api/hosts/${id}/traffic?range=${range}`);
      return data;
    },
    refetchInterval: 10_000,
  });
}

export function useHostAnomalyHistory(id: string, range: string) {
  return useQuery({
    queryKey: queryKeys.hosts.anomaly(id, range),
    queryFn: async (): Promise<TimeSeries> => {
      const { data } = await api.get(`/api/hosts/${id}/anomaly-history?range=${range}`);
      return data;
    },
    refetchInterval: 10_000,
  });
}

export function useHostAlerts(id: string) {
  return useQuery({
    queryKey: queryKeys.hosts.alerts(id),
    queryFn: async (): Promise<Alert[]> => {
      const { data } = await api.get(`/api/hosts/${id}/alerts`);
      return data;
    },
    refetchInterval: 10_000,
  });
}

export function useUpdateHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      custom_tag,
      parent_host_id,
    }: {
      id: string;
      custom_tag?: string | null;
      parent_host_id?: string | null;
    }) => {
      const { data } = await api.patch(`/api/hosts/${id}`, { custom_tag, parent_host_id });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.hosts.all });
      qc.invalidateQueries({ queryKey: queryKeys.devices.all });
      qc.refetchQueries({ queryKey: queryKeys.hosts.all });
    },
  });
}
