import { create } from 'zustand';
import type { Alert } from '@/types';

interface DeviceNotification {
  id: string;
  hostname: string;
  ip: string;
  timestamp: number;
}

interface AlertStreamState {
  liveAlerts: Alert[];
  unreadCount: number;
  deviceNotifications: DeviceNotification[];
  appendAlert: (alert: Alert) => void;
  markAllRead: () => void;
  ackAlert: (id: string) => void;
  resolveAlert: (id: string) => void;
  addDeviceNotification: (n: DeviceNotification) => void;
  dismissDeviceNotification: (id: string) => void;
}

const MAX_LIVE_ALERTS = 200;

export const useAlertStreamStore = create<AlertStreamState>((set) => ({
  liveAlerts: [],
  unreadCount: 0,
  deviceNotifications: [],

  appendAlert: (alert) =>
    set((state) => {
      const exists = state.liveAlerts.findIndex((a) => a.id === alert.id);
      let updated: Alert[];
      if (exists >= 0) {
        updated = [...state.liveAlerts];
        updated[exists] = alert;
      } else {
        updated = [alert, ...state.liveAlerts].slice(0, MAX_LIVE_ALERTS);
      }
      return {
        liveAlerts: updated,
        unreadCount: exists >= 0 ? state.unreadCount : state.unreadCount + 1,
      };
    }),

  // Reading a notification must not discard a real alert before the analyst
  // can open it; the stream remains an in-session, live-event history.
  markAllRead: () => set({ unreadCount: 0 }),

  ackAlert: (id) =>
    set((state) => ({
      liveAlerts: state.liveAlerts.map((a) => (a.id === id ? { ...a, status: 'ack' as const } : a)),
    })),

  resolveAlert: (id) =>
    set((state) => ({
      liveAlerts: state.liveAlerts.map((a) => (a.id === id ? { ...a, status: 'resolved' as const } : a)),
    })),

  addDeviceNotification: (n) =>
    set((state) => ({
      deviceNotifications: [n, ...state.deviceNotifications].slice(0, 5),
    })),

  dismissDeviceNotification: (id) =>
    set((state) => ({
      deviceNotifications: state.deviceNotifications.filter((n) => n.id !== id),
    })),
}));
