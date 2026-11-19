import { create } from 'zustand';
import type { SentryMode } from '@/config/constants';

interface SentryStatusState {
  mode: SentryMode;
  baselineProgress: number;
  uptime: number;
  activeHosts: number;
  modelVersions: Record<string, string>;
  setStatus: (status: Partial<SentryStatusState>) => void;
}

export const useSentryStatusStore = create<SentryStatusState>((set) => ({
  mode: 'monitoring',
  baselineProgress: 0,
  uptime: 0,
  activeHosts: 0,
  modelVersions: {},
  setStatus: (status) => set(status),
}));
