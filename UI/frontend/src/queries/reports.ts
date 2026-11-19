import { useQuery } from '@tanstack/react-query';
import { queryKeys } from './keys';
import { api } from '@/lib/axios';
import type { ReportResponse } from '@/types';

export function useInvestorReport() {
  return useQuery({
    queryKey: queryKeys.reports.investor('30d'),
    queryFn: async (): Promise<ReportResponse> => {
      const { data } = await api.get('/api/reports/investor');
      return data;
    },
    staleTime: 60_000,
  });
}
