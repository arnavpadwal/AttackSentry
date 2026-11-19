import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import type { Incident, IncidentSummary, Alert, Playbook, Mitigation } from '@/types';

export interface IncidentFilters {
  status?: string;
  severity?: string;
  family?: string;
  q?: string;
  sort?: 'recent' | 'severity';
  limit?: number;
  offset?: number;
}

export function useIncidents(filters: IncidentFilters = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.list(filters as Record<string, unknown>),
    queryFn: async (): Promise<Incident[]> => {
      const { data } = await api.get('/api/incidents', { params: filters });
      return data;
    },
    refetchInterval: 10_000,
    staleTime: 5_000,
  });
}

export function useIncidentSummary() {
  return useQuery({
    queryKey: queryKeys.incidents.summary,
    queryFn: async (): Promise<IncidentSummary> => (await api.get('/api/incidents/summary')).data,
    refetchInterval: 10_000,
    staleTime: 5_000,
  });
}

export function useIncident(id: string) {
  return useQuery({
    queryKey: queryKeys.incidents.detail(id),
    queryFn: async (): Promise<Incident> => {
      const { data } = await api.get(`/api/incidents/${id}`);
      return data;
    },
    enabled: Boolean(id),
  });
}

export function useIncidentPlaybook(id: string) {
  return useQuery({
    queryKey: queryKeys.incidents.playbook(id),
    queryFn: async (): Promise<Playbook> => {
      const { data } = await api.get(`/api/incidents/${id}/playbook`);
      return data;
    },
    enabled: Boolean(id),
    retry: false,
  });
}

export function useGenerateIncidentPlaybook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string): Promise<Playbook> =>
      (await api.post(`/api/incidents/${id}/playbook/generate`)).data,
    onSuccess: (_playbook, id) => {
      qc.invalidateQueries({ queryKey: queryKeys.incidents.playbook(id) });
    },
  });
}

export function useIncidentAlerts(id: string) {
  return useQuery({
    queryKey: queryKeys.incidents.alerts(id),
    queryFn: async (): Promise<Alert[]> => {
      const { data } = await api.get(`/api/incidents/${id}/alerts`);
      return data;
    },
  });
}

export function useUpdateIncidentStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const { data } = await api.patch(`/api/incidents/${id}/status`, { status });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.incidents.all });
    },
  });
}

export function useBulkUpdateIncidents() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ ids, status }: { ids: string[]; status: string }) => {
      const { data } = await api.patch('/api/incidents/bulk/status', { incident_ids: ids, status });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.incidents.all }),
  });
}

export function useMitigations() {
  return useQuery({
    queryKey: queryKeys.mitigations.all,
    queryFn: async (): Promise<Mitigation[]> => (await api.get('/api/mitigations')).data,
    refetchInterval: 10_000,
  });
}

export function useRequestMitigation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (request: { incident_id: string; action: string; reason: string; ttl_minutes?: number }) =>
      (await api.post('/api/mitigations', request)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.mitigations.all }),
  });
}

export function useMitigationDecision() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, decision }: { id: string; decision: 'approve' | 'cancel' | 'release' }) =>
      (await api.post(`/api/mitigations/${id}/${decision}`)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.mitigations.all }),
  });
}
