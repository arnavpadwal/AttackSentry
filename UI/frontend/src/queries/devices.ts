import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import type { Device } from '@/types';

export function usePendingDevices() {
  return useQuery({
    queryKey: queryKeys.devices.pending,
    queryFn: async (): Promise<Device[]> => {
      const { data } = await api.get('/api/devices/pending');
      return data;
    },
    refetchInterval: 5_000,
    staleTime: 0,
  });
}

export function useDevices() {
  return useQuery({
    queryKey: queryKeys.devices.all,
    queryFn: async (): Promise<Device[]> => {
      const { data } = await api.get('/api/devices');
      return data;
    },
    refetchInterval: 10_000,
    staleTime: 5_000,
  });
}

export function useApproveDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      timeout_hours,
      caveat,
      parent_device_id,
    }: {
      id: string;
      timeout_hours?: number;
      caveat?: string;
      parent_device_id?: string | null;
    }) => {
      const { data } = await api.post(`/api/devices/${id}/approve`, {
        timeout_hours,
        whitelist: false,
        caveat,
        parent_device_id,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.devices.pending });
      qc.invalidateQueries({ queryKey: queryKeys.devices.all });
      qc.invalidateQueries({ queryKey: queryKeys.hosts.all });
    },
  });
}

export function useRejectDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post(`/api/devices/${id}/reject`);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.devices.pending });
    },
  });
}

export function useUpdateDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      custom_tag,
      parent_device_id,
    }: {
      id: string;
      custom_tag?: string | null;
      parent_device_id?: string | null;
    }) => {
      const { data } = await api.patch(`/api/devices/${id}`, { custom_tag, parent_device_id });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.devices.all });
      qc.invalidateQueries({ queryKey: queryKeys.hosts.all });
    },
  });
}
