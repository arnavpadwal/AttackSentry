import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import { useDevices, usePendingDevices, useApproveDevice, useRejectDevice } from '@/queries/devices';

export default function DevicesPage() {
  const { data: pending } = usePendingDevices();
  const { data: approved } = useDevices();
  const approve = useApproveDevice();
  const reject = useRejectDevice();

  return (
    <div className="animate-fade-in space-y-6">
      <div>
        <h1 className="page-title">Devices</h1>
        <p className="page-subtitle">Endpoint approval and whitelisting</p>
      </div>

      <Card title={`Pending approval (${pending?.length ?? 0})`} noPadding>
        {pending?.length ? (
          <ul className="divide-y divide-border">
            {pending.map((d) => (
              <li key={d.id} className="flex items-center justify-between px-5 py-3">
                <div>
                  <p className="text-sm font-medium text-ink">{d.hostname}</p>
                  <p className="text-xs text-ink-faint">{d.ip} · {d.os}</p>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="secondary" onClick={() => reject.mutate(d.id)}>Reject</Button>
                  <Button size="sm" onClick={() => approve.mutate({ id: d.id })}>Approve</Button>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="p-6 text-center text-sm text-ink-faint">No devices awaiting approval</p>
        )}
      </Card>

      <Card title={`Approved devices (${approved?.length ?? 0})`} noPadding>
        {approved?.length ? (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="table-header-cell text-left">Hostname</th>
                <th className="table-header-cell text-left">IP</th>
                <th className="table-header-cell text-left">OS</th>
                <th className="table-header-cell text-left">Tag</th>
                <th className="table-header-cell text-right">Status</th>
              </tr>
            </thead>
            <tbody>
              {approved.map((d) => (
                <tr key={d.id} className="border-b border-border last:border-0">
                  <td className="px-5 py-2.5 text-sm text-ink">{d.hostname}</td>
                  <td className="px-5 py-2.5 text-sm text-ink-2">{d.ip}</td>
                  <td className="px-5 py-2.5 text-sm text-ink-2">{d.os}</td>
                  <td className="px-5 py-2.5 text-sm text-ink-2">{d.custom_tag ?? '—'}</td>
                  <td className="px-5 py-2.5 text-right"><Badge variant="default">approved</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="p-6 text-center text-sm text-ink-faint">No approved devices</p>
        )}
      </Card>
    </div>
  );
}
