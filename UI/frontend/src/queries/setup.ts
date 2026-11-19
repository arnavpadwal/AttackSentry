import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/axios';

export function useSetupStatus() {
  return useQuery({
    queryKey: ['setupStatus'],
    queryFn: async () => {
      const { data } = await api.get('/api/setup/status');
      return data as { is_setup_complete: boolean };
    },
    staleTime: Infinity,
  });
}
