import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/axios';

export interface GraphNode {
  id: string;
  ip: string;
  hostname: string;
  group: string;
  risk: number;
  status: string;
  external: boolean;
  node_type?: 'host' | 'group' | 'external';
  vlan?: string | null;
}

export interface GraphEdge {
  id: string;
  src: string;
  dst: string;
  flows: number;
  bytes: number;
  relation?: string;
}

export interface NetworkGraph { nodes: GraphNode[]; edges: GraphEdge[]; }

export interface MitreTechnique { tactic: string; technique: string; count: number; }
export interface MitreTactic { tactic: string; count: number; pct: number; }
export interface MitreCoverage { tactics: MitreTactic[]; techniques: MitreTechnique[]; total: number; }

export function useNetworkGraph() {
  return useQuery({
    queryKey: ['network', 'graph'],
    queryFn: async (): Promise<NetworkGraph> => {
      const { data } = await api.get('/api/network/graph');
      return data;
    },
    refetchInterval: 10_000,
    staleTime: 5_000,
  });
}

export function useMitreCoverage() {
  return useQuery({
    queryKey: ['mitre', 'coverage'],
    queryFn: async (): Promise<MitreCoverage> => {
      const { data } = await api.get('/api/mitre/coverage');
      return data;
    },
    refetchInterval: 15_000,
    staleTime: 5_000,
  });
}
