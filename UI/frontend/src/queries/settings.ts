import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import type { Settings, Sensor, SuppressionRule, User } from '@/types';

export function useSettings() {
  return useQuery({
    queryKey: queryKeys.settings.all,
    queryFn: async (): Promise<Settings> => {
      const { data } = await api.get('/api/settings');
      return data;
    },
    staleTime: 30_000,
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (settings: Partial<Settings> & { webhook_secret?: string; llm_api_key?: string }) => {
      const { data } = await api.patch('/api/settings', settings);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.all }),
  });
}

export function useTestLLM() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/api/settings/test-llm');
      return data as { healthy: boolean; message: string };
    },
  });
}

export function useTestWebhook() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/api/settings/test-webhook');
      return data as { healthy: boolean; message: string };
    },
  });
}

export function useSensors() {
  return useQuery({
    queryKey: queryKeys.sensors.all,
    queryFn: async (): Promise<Sensor[]> => {
      const { data } = await api.get('/api/sensors');
      return data;
    },
    refetchInterval: 15_000,
  });
}

export function useCreateSensor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (sensor: { name: string; sensor_type: string }) => (await api.post('/api/sensors', sensor)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.sensors.all }),
  });
}

export function useSuppressions() {
  return useQuery({
    queryKey: queryKeys.suppressions.all,
    queryFn: async (): Promise<SuppressionRule[]> => {
      const { data } = await api.get('/api/suppressions');
      return data;
    },
  });
}

export function useCreateSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (rule: Partial<SuppressionRule>) => {
      const { data } = await api.post('/api/suppressions', rule);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.suppressions.all }),
  });
}

export function useDeleteSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/api/suppressions/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.suppressions.all }),
  });
}

export function useUsers(enabled = true) {
  return useQuery({
    queryKey: queryKeys.settings.users,
    queryFn: async (): Promise<User[]> => {
      const { data } = await api.get('/api/users');
      return data;
    },
    enabled,
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (user: { username: string; email: string; password: string; role: string; full_name?: string }) => {
      const { data } = await api.post('/api/users', user);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.users }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...patch }: { id: string; role?: string; is_active?: boolean; password?: string; full_name?: string; email?: string }) => {
      const { data } = await api.patch(`/api/users/${id}`, patch);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.users }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => { await api.delete(`/api/users/${id}`); },
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.users }),
  });
}
