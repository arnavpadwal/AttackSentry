import { Bell, X } from 'lucide-react';
import { useAlertStreamStore } from '@/stores';
import { relativeTime } from '@/lib/utils';

export default function DeviceNotificationToast() {
  const notifications = useAlertStreamStore((s) => s.deviceNotifications);
  const dismiss = useAlertStreamStore((s) => s.dismissDeviceNotification);

  if (notifications.length === 0) return null;

  return (
    <div className="fixed right-6 top-24 z-50 flex flex-col gap-4">
      {notifications.map((n) => (
        <div
          key={n.id}
          className="animate-fade-in flex w-80 items-start gap-4"
          style={{
            background: '#ffffff',
            border: '1px solid var(--color-surface-border)',
            borderRadius: 12,
            padding: '16px 20px',
            boxShadow: '0 8px 30px rgba(56,128,135,0.15)',
          }}
        >
          <div
            className="mt-0.5 flex shrink-0 items-center justify-center rounded-full"
            style={{ width: 32, height: 32, background: 'rgba(230,168,23,0.15)', color: '#e6a817' }}
          >
            <Bell size={16} />
          </div>
          <div className="min-w-0 flex-1">
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>
              New Device Request
            </p>
            <p style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginTop: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {n.hostname} · {n.ip}
            </p>
            <p style={{ fontSize: 11.5, color: 'var(--color-text-tertiary)', marginTop: 6 }}>
              {relativeTime(n.timestamp)}
            </p>
          </div>
          <button
            onClick={() => dismiss(n.id)}
            style={{ color: 'var(--color-text-tertiary)', padding: 4, margin: -4 }}
            className="transition-colors hover:text-slate-800"
          >
            <X size={16} />
          </button>
        </div>
      ))}
    </div>
  );
}
