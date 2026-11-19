import { create } from 'zustand';
import type { Flow } from '@/types';

interface TelemetryState {
  flows: Flow[];
  aggregated: {
    bytesPerSec: number[];
    bytesInPerSec: number[];
    bytesOutPerSec: number[];
    timestamps: number[];
    activeProtocols: Record<string, number>;
  };
  appendFlows: (newFlows: Flow[]) => void;
  clearFlows: () => void;
}

const MAX_FLOWS = 3000;
const WINDOW_SECONDS = 90;

/** Merge flows into one-second buckets so the chart is a real time series. */
export const useTelemetryStore = create<TelemetryState>((set) => ({
  flows: [],
  aggregated: { bytesPerSec: [], bytesInPerSec: [], bytesOutPerSec: [], timestamps: [], activeProtocols: {} },

  appendFlows: (newFlows) =>
    set((state) => {
      const allFlows = [...state.flows, ...newFlows].slice(-MAX_FLOWS);
      const now = Math.floor(Date.now() / 1000);
      const buckets = new Map<number, { bytesIn: number; bytesOut: number }>();

      state.aggregated.timestamps.forEach((timestamp, index) => {
        buckets.set(Math.floor(timestamp), {
          bytesIn: state.aggregated.bytesInPerSec[index] ?? 0,
          bytesOut: state.aggregated.bytesOutPerSec[index] ?? 0,
        });
      });

      const protocols = { ...state.aggregated.activeProtocols };
      newFlows.forEach((flow) => {
        const timestamp = Math.floor(Number(flow.timestamp) || now);
        const bucket = buckets.get(timestamp) ?? { bytesIn: 0, bytesOut: 0 };
        bucket.bytesIn += flow.bytes_in || 0;
        bucket.bytesOut += flow.bytes_out || 0;
        buckets.set(timestamp, bucket);
        protocols[flow.protocol] = (protocols[flow.protocol] || 0) + (flow.bytes_in || 0) + (flow.bytes_out || 0);
      });

      const cutoff = now - WINDOW_SECONDS;
      const points = [...buckets.entries()]
        .filter(([timestamp]) => timestamp >= cutoff)
        .sort(([a], [b]) => a - b);

      return {
        flows: allFlows,
        aggregated: {
          timestamps: points.map(([timestamp]) => timestamp),
          bytesInPerSec: points.map(([, bucket]) => bucket.bytesIn),
          bytesOutPerSec: points.map(([, bucket]) => bucket.bytesOut),
          bytesPerSec: points.map(([, bucket]) => bucket.bytesIn + bucket.bytesOut),
          activeProtocols: protocols,
        },
      };
    }),

  clearFlows: () =>
    set({ flows: [], aggregated: { bytesPerSec: [], bytesInPerSec: [], bytesOutPerSec: [], timestamps: [], activeProtocols: {} } }),
}));
