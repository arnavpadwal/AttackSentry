import type { AlertFilters } from '@/types';

export const queryKeys = {
  health: ['health'] as const,

  devices: {
    all: ['devices'] as const,
    pending: ['devices', 'pending'] as const,
    detail: (id: string) => ['devices', 'detail', id] as const,
  },

  hosts: {
    all: ['hosts'] as const,
    detail: (id: string) => ['hosts', 'detail', id] as const,
    traffic: (id: string, range: string) => ['hosts', id, 'traffic', range] as const,
    alerts: (id: string, range?: string) => ['hosts', id, 'alerts', range] as const,
    anomaly: (id: string, range: string) => ['hosts', id, 'anomaly', range] as const,
  },

  alerts: {
    list: (filters: AlertFilters) => ['alerts', filters] as const,
    detail: (id: string) => ['alerts', 'detail', id] as const,
    playbook: (id: string) => ['alerts', id, 'playbook'] as const,
    export: (format: string, range: string) => ['alerts', 'export', format, range] as const,
  },

  incidents: {
    all: ['incidents'] as const,
    summary: ['incidents', 'summary'] as const,
    list: (filters: Record<string, unknown>) => ['incidents', 'list', filters] as const,
    detail: (id: string) => ['incidents', 'detail', id] as const,
    alerts: (id: string) => ['incidents', id, 'alerts'] as const,
    playbook: (id: string) => ['incidents', id, 'playbook'] as const,
  },

  mitigations: {
    all: ['mitigations'] as const,
  },

  sensors: {
    all: ['sensors'] as const,
  },

  suppressions: {
    all: ['suppressions'] as const,
  },

  sentry: {
    status: ['sentry', 'status'] as const,
    baseline: ['sentry', 'baseline'] as const,
  },

  reports: {
    investor: (range: string) => ['reports', 'investor', range] as const,
  },

  settings: {
    all: ['settings'] as const,
    users: ['settings', 'users'] as const,
  },

  traffic: {
    summary: (range: string) => ['traffic', 'summary', range] as const,
  },
} as const;
