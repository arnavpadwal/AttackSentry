import { useParams, useNavigate } from 'react-router-dom';
import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import Gauge from '@/components/shared/Gauge';
import { useHost, useHostAnomalyHistory, useHostAlerts } from '@/queries/hosts';
import { useIncidents } from '@/queries/incidents';
import { useNetworkGraph } from '@/queries/network';
import { displayFamily, parseTimestamp, relativeTime } from '@/lib/utils';
import { ArrowLeft } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';

export default function HostDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: host } = useHost(id!);
  const { data: anomaly } = useHostAnomalyHistory(id!, '24h');
  const { data: hostAlerts } = useHostAlerts(id!);
  const { data: incidents } = useIncidents();
  const { data: graph } = useNetworkGraph();

  if (!host) return <p className="p-8 text-center text-ink-faint">Host not found</p>;

  const hostIncidents = incidents?.filter((i) => i.entity === host.ip_address) ?? [];
  const anomalyData = anomaly?.timestamps.map((t, i) => ({ t: new Date(t * 1000).toLocaleTimeString(), score: anomaly.values[i] })) ?? [];

  const related = (graph?.edges ?? [])
    .filter((e) => e.src === host.ip_address || e.dst === host.ip_address)
    .map((e) => (e.src === host.ip_address ? e.dst : e.src))
    .filter((ip: string, i: number, a: string[]) => a.indexOf(ip) === i)
    .slice(0, 10);

  return (
    <div className="animate-fade-in space-y-6">
      <button onClick={() => navigate(-1)} className="flex items-center gap-1.5 text-sm text-ink-2 hover:text-ink">
        <ArrowLeft size={16} /> Back
      </button>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="page-title">{host.hostname || host.ip_address}</h1>
            <Badge variant={host.risk_score >= 75 ? 'critical' : host.risk_score >= 40 ? 'high' : host.risk_score >= 15 ? 'medium' : 'low'}>
              {host.risk_score >= 40 ? 'elevated' : 'normal'}
            </Badge>
          </div>
          <p className="page-subtitle">{host.ip_address} · {host.group_name ?? 'Unknown group'} · {host.os_info ?? 'unknown OS'}</p>
        </div>
        <Gauge value={host.risk_score} size={110} label="Entity risk" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Anomaly history (24h)" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={anomalyData}>
              <XAxis dataKey="t" hide />
              <YAxis hide />
              <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="score" stroke="var(--color-accent)" strokeWidth={1.5} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Identity & context">
          <dl className="space-y-2.5 text-sm">
            <div className="flex justify-between"><dt className="text-ink-faint">Identity</dt><dd className="text-ink">{host.identity ?? '—'}</dd></div>
            <div className="flex justify-between"><dt className="text-ink-faint">Device type</dt><dd className="text-ink">{host.device_type ?? '—'}</dd></div>
            <div className="flex justify-between"><dt className="text-ink-faint">OS</dt><dd className="text-ink">{host.os_info ?? '—'}</dd></div>
            <div className="flex justify-between"><dt className="text-ink-faint">Status</dt><dd className="text-ink">{host.status}</dd></div>
            <div className="flex justify-between"><dt className="text-ink-faint">Baseline</dt><dd className="text-ink">{host.baseline_status}</dd></div>
            <div className="flex justify-between"><dt className="text-ink-faint">Last seen</dt><dd className="text-ink">{host.last_seen ? relativeTime(parseTimestamp(host.last_seen)) : '—'}</dd></div>
          </dl>
        </Card>
      </div>

      <Card title="Why this host is scored this way" subtitle="Signals contributing to the current entity risk score">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-lg bg-surface-subtle p-3"><p className="text-xs text-ink-faint">Current risk</p><p className="mt-1 text-lg font-semibold text-ink">{host.risk_score.toFixed(0)} / 100</p></div>
          <div className="rounded-lg bg-surface-subtle p-3"><p className="text-xs text-ink-faint">Detections (24h)</p><p className="mt-1 text-lg font-semibold text-ink">{host.alert_count}</p></div>
          <div className="rounded-lg bg-surface-subtle p-3"><p className="text-xs text-ink-faint">Incidents</p><p className="mt-1 text-lg font-semibold text-ink">{host.incident_count}</p></div>
        </div>
        <p className="mt-4 text-sm leading-6 text-ink-2">Risk combines anomaly deviation from the host baseline, calibrated detection confidence, incident recurrence, and peer context. The most recent contributing reasons are shown below.</p>
        {hostAlerts?.slice(0, 3).map((a) => <div key={a.id} className="mt-3 rounded-lg border border-border p-3"><div className="flex items-center justify-between gap-3"><span className="text-sm font-medium text-ink">{a.detection_type}</span><Badge variant={a.severity}>{a.severity}</Badge></div><p className="mt-1 text-xs leading-5 text-ink-faint">{a.reason || 'Behavioral deviation detected against the learned baseline.'}</p></div>)}
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title={`Incidents (${hostIncidents.length})`} className="lg:col-span-2" noPadding>
          {hostIncidents.length ? (
            <table className="dense-table w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-5 py-2 text-left">Severity</th>
                  <th className="px-5 py-2 text-left">Family</th>
                  <th className="px-5 py-2 text-right">Count</th>
                  <th className="px-5 py-2 text-right">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {hostIncidents.map((i) => (
                  <tr key={i.id} className="border-b border-border last:border-0">
                    <td className="px-5 py-2"><Badge variant={i.severity}>{i.severity}</Badge></td>
                    <td className="px-5 py-2 text-ink">{displayFamily(i.family)}</td>
                    <td className="px-5 py-2 text-right text-ink">{i.count}</td>
                    <td className="px-5 py-2 text-right text-ink-faint">{relativeTime(parseTimestamp(i.last_seen))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="p-6 text-center text-sm text-ink-faint">No incidents for this entity</p>}
        </Card>

        <Card title="Recent detections" noPadding>
          {hostAlerts?.length ? (
            <ul className="divide-y divide-border">
              {hostAlerts.slice(0, 6).map((a) => (
                <li key={a.id} className="flex cursor-pointer items-center justify-between px-4 py-2 hover:bg-surface-subtle" onClick={() => navigate(`/alerts/${a.id}`)}>
                  <div className="min-w-0">
                    <p className="truncate text-sm text-ink">{a.detection_type}</p>
                    <p className="text-xs text-ink-faint">{relativeTime(parseTimestamp(a.timestamp))}</p>
                  </div>
                  <Badge variant={a.severity}>{a.severity}</Badge>
                </li>
              ))}
            </ul>
          ) : <p className="p-6 text-center text-sm text-ink-faint">No detections</p>}
        </Card>
      </div>

      <Card title="Related entities" subtitle="peers this host has communicated with">
        {related.length ? (
          <div className="flex flex-wrap gap-2">
            {related.map((ip) => (
              <button key={ip} className="rounded-lg border border-border bg-surface-subtle px-3 py-1.5 text-sm text-ink hover:border-accent"
                onClick={() => { const n = graph?.nodes.find((x) => x.ip === ip); if (n && !n.external) navigate(`/hosts/${n.id}`); }}>
                {ip}
              </button>
            ))}
          </div>
        ) : <p className="text-sm text-ink-faint">No recent relationships</p>}
      </Card>
    </div>
  );
}
