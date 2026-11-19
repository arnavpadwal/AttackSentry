import { Server, ShieldCheck } from 'lucide-react';
import PageHeader from '@/components/shared/PageHeader';
import Metric from '@/components/shared/Metric';
import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import EmptyState from '@/components/shared/EmptyState';
import StatusDot from '@/components/shared/StatusDot';
import { Skeleton } from '@/components/ui/skeleton';
import { useApproveDevice, useDevices, usePendingDevices, useRejectDevice } from '@/queries/devices';
import { useSensors } from '@/queries/settings';
import { formatNumber, parseTimestamp, relativeTime } from '@/lib/utils';
import type { Sensor } from '@/types';

const STALE_MS = 5 * 60_000;

const stateLabel = { online: 'Online', stale: 'Stale', offline: 'Offline' } as const;

function sensorState(sensor: Sensor): keyof typeof stateLabel {
  if (sensor.status !== 'online') return 'offline';
  const beat = parseTimestamp(sensor.last_heartbeat);
  if (!beat) return 'stale';
  return Date.now() - beat > STALE_MS ? 'stale' : 'online';
}

export default function DevicesPage() {
  const { data: pending, isLoading: pendingLoading, isError: pendingError } = usePendingDevices();
  const { data: approved, isLoading: approvedLoading, isError: approvedError } = useDevices();
  const { data: sensors, isLoading: sensorsLoading, isError: sensorsError } = useSensors();
  const approve = useApproveDevice();
  const reject = useRejectDevice();

  const fleet = sensors ?? [];
  const online = fleet.filter((sensor) => sensorState(sensor) === 'online').length;
  const lastBeat = fleet.reduce((latest, sensor) => Math.max(latest, parseTimestamp(sensor.last_heartbeat)), 0);
  const flowsPerSecond = fleet.reduce((sum, sensor) => sum + sensor.flows_per_second, 0);
  const totalFlows = fleet.reduce((sum, sensor) => sum + sensor.total_flows, 0);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Sensors"
        description="Capture agents reporting to this console, and endpoints waiting on approval."
        meta={(
          <span className="meta">
            {fleet.length ? `${online} of ${fleet.length} online` : 'No sensors registered'}
            {lastBeat ? ` · last check-in ${relativeTime(lastBeat)}` : ''}
          </span>
        )}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Sensors online" value={online} hint={`of ${fleet.length} registered`} tone={online ? 'ok' : 'default'} />
        <Metric
          label="Stale or offline"
          value={fleet.length - online}
          hint={fleet.length ? 'No check-in in 5m, or reported down' : 'Nothing to report on yet'}
        />
        <Metric label="Pending approval" value={pending?.length ?? 0} hint="Endpoints awaiting review" />
        <Metric label="Flows per second" value={formatNumber(flowsPerSecond)} hint={`${formatNumber(totalFlows)} flows observed`} />
      </div>

      <Card
        title="Sensor fleet"
        subtitle="Registered capture agents and their connection state"
        action={<Badge>{fleet.length} registered</Badge>}
        noPadding
      >
        {sensorsLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2].map((row) => <Skeleton key={row} className="h-8 w-full" />)}
          </div>
        ) : sensorsError ? (
          <p className="p-4 text-[12px] text-muted-foreground">Sensor inventory is unavailable. Check the core API and refresh.</p>
        ) : fleet.length ? (
          <div className="overflow-x-auto">
            <table className="table-shell">
              <thead>
                <tr>
                  <th>Sensor</th>
                  <th>Host</th>
                  <th>Status</th>
                  <th>Version</th>
                  <th className="text-right">Flows/s</th>
                  <th className="text-right">Last check-in</th>
                </tr>
              </thead>
              <tbody>
                {fleet.map((sensor) => {
                  const state = sensorState(sensor);
                  return (
                    <tr key={sensor.id}>
                      <td>
                        <p className="text-[12.5px] font-medium text-foreground">{sensor.name}</p>
                        <p className="meta capitalize">{sensor.sensor_type}</p>
                      </td>
                      <td className="mono text-[11.5px] text-muted-foreground">
                        {sensor.hostname ? (
                          <>
                            <p>{sensor.hostname}</p>
                            {sensor.ip_address ? <p>{sensor.ip_address}</p> : null}
                          </>
                        ) : (
                          <p>{sensor.ip_address ?? '—'}</p>
                        )}
                      </td>
                      <td>
                        <StatusDot
                          status={state === 'online' ? 'online' : state === 'stale' ? 'degraded' : 'offline'}
                          label={stateLabel[state]}
                          size="sm"
                        />
                      </td>
                      <td className="mono text-[11.5px] text-muted-foreground">{sensor.version ?? '—'}</td>
                      <td className="text-right tabular-nums">{formatNumber(sensor.flows_per_second)}</td>
                      <td className="text-right text-[11.5px] tabular-nums text-muted-foreground">
                        {sensor.last_heartbeat ? relativeTime(parseTimestamp(sensor.last_heartbeat)) : 'Never'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={Server}
            title="No sensors reporting"
            description="Register a sensor in Settings → Sensors, then download its configuration for the host."
            action={<a href="/settings" className="text-[12px] font-medium text-primary hover:underline">Open Settings</a>}
          />
        )}
      </Card>

      <Card
        title="Pending approval"
        subtitle="Endpoints that have not been authorized yet"
        action={<Badge>{pending?.length ?? 0} pending</Badge>}
        noPadding
      >
        {pendingLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1].map((row) => <Skeleton key={row} className="h-8 w-full" />)}
          </div>
        ) : pendingError ? (
          <p className="p-4 text-[12px] text-muted-foreground">Pending endpoints could not be loaded. Refresh to try again.</p>
        ) : pending?.length ? (
          <div className="overflow-x-auto">
            <table className="table-shell">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>IP</th>
                  <th>OS</th>
                  <th className="text-right">First seen</th>
                  <th className="text-right">Decision</th>
                </tr>
              </thead>
              <tbody>
                {pending.map((device) => (
                  <tr key={device.id}>
                    <td className="text-[12.5px] font-medium text-foreground">{device.hostname}</td>
                    <td className="mono text-[11.5px] text-muted-foreground">{device.ip}</td>
                    <td className="text-[12.5px] capitalize text-muted-foreground">{device.os}</td>
                    <td className="text-right text-[11.5px] tabular-nums text-muted-foreground">
                      {device.first_seen ? relativeTime(parseTimestamp(device.first_seen)) : '—'}
                    </td>
                    <td className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => reject.mutate(device.id)}>Reject</Button>
                        <Button size="sm" onClick={() => approve.mutate({ id: device.id })}>Approve</Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={ShieldCheck}
            title="No devices awaiting approval"
            description="New endpoints appear here the first time they send traffic, until an operator approves them."
          />
        )}
      </Card>

      <Card
        title="Approved endpoints"
        subtitle="Endpoints approved on this console"
        action={<Badge>{approved?.length ?? 0} approved</Badge>}
        noPadding
      >
        {approvedLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2].map((row) => <Skeleton key={row} className="h-8 w-full" />)}
          </div>
        ) : approvedError ? (
          <p className="p-4 text-[12px] text-muted-foreground">Approved endpoints could not be loaded. Refresh to try again.</p>
        ) : approved?.length ? (
          <div className="overflow-x-auto">
            <table className="table-shell">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>IP</th>
                  <th>OS</th>
                  <th>Tag</th>
                  <th className="text-right">Approved</th>
                  <th className="text-right">Status</th>
                </tr>
              </thead>
              <tbody>
                {approved.map((device) => (
                  <tr key={device.id}>
                    <td className="text-[12.5px] font-medium text-foreground">{device.hostname}</td>
                    <td className="mono text-[11.5px] text-muted-foreground">{device.ip}</td>
                    <td className="text-[12.5px] capitalize text-muted-foreground">{device.os}</td>
                    <td className="text-[12.5px] text-muted-foreground">{device.custom_tag ?? '—'}</td>
                    <td className="text-right text-[11.5px] tabular-nums text-muted-foreground">
                      {device.approved_at ? relativeTime(parseTimestamp(device.approved_at)) : '—'}
                      {device.timeout_hours ? <span className="meta block">Temporary · {device.timeout_hours}h</span> : null}
                    </td>
                    <td className="text-right"><Badge>approved</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={ShieldCheck}
            title="No approved endpoints"
            description="Approve a pending endpoint and it will be listed here."
          />
        )}
      </Card>
    </div>
  );
}
