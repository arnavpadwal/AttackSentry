import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import type { Alert, AlertFilters, PaginatedResponse, Playbook } from '@/types';

export function useAlerts(filters: AlertFilters) {
  const params = new URLSearchParams();
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.status) params.set('status', filters.status);
  if (filters.expert) params.set('expert', filters.expert);
  if (filters.entity) params.set('entity', filters.entity);
  if (filters.page) params.set('page', String(filters.page));
  if (filters.page_size) params.set('page_size', String(filters.page_size));
  if (filters.range) params.set('range', filters.range);

  return useQuery({
    queryKey: queryKeys.alerts.list(filters),
    queryFn: async (): Promise<PaginatedResponse<Alert>> => {
      const { data } = await api.get(`/api/alerts?${params.toString()}`);
      return data;
    },
    refetchInterval: 10_000,
    staleTime: 0,
  });
}

export function useAlert(id: string) {
  return useQuery({
    queryKey: queryKeys.alerts.detail(id),
    queryFn: async (): Promise<Alert> => {
      const { data } = await api.get(`/api/alerts/${id}`);
      return data;
    },
    staleTime: 60_000,
  });
}

export function useUpdateAlertStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const { data } = await api.patch(`/api/alerts/${id}/status`, { status });
      return data;
    },
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: queryKeys.alerts.detail(id) });
      qc.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

export function useAlertPlaybook(id: string) {
  return useQuery({
    queryKey: queryKeys.alerts.playbook(id),
    queryFn: async (): Promise<Playbook> => {
      const { data } = await api.get(`/api/alerts/${id}/playbook`);
      return data;
    },
    staleTime: 60_000,
  });
}
