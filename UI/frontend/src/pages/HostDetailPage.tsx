import { useMemo, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Inbox, ServerOff, ShieldCheck } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import PageHeader from '@/components/shared/PageHeader';
import Metric from '@/components/shared/Metric';
import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import EmptyState from '@/components/shared/EmptyState';
import Gauge from '@/components/shared/Gauge';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { useHost, useHostAnomalyHistory, useHostAlerts } from '@/queries/hosts';
import { useIncidents } from '@/queries/incidents';
import { useNetworkGraph } from '@/queries/network';
import { displayFamily, parseTimestamp, relativeTime, cn } from '@/lib/utils';
import type { Alert } from '@/types';

type RiskBand = 'critical' | 'high' | 'medium' | 'low';

const RISK_LABEL: Record<RiskBand, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const SEVERITY_RAIL: Record<string, string> = {
  critical: 'border-severity-critical',
  high: 'border-severity-high',
  medium: 'border-severity-medium',
  low: 'border-severity-low',
  info: 'border-severity-info',
};

function riskValue(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score || 0)));
}

function riskBand(score: number): RiskBand {
  const value = riskValue(score);
  if (value >= 75) return 'critical';
  if (value >= 50) return 'high';
  if (value >= 25) return 'medium';
  return 'low';
}

function DetailsRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-[11.5px] text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate text-right text-[11.5px] text-foreground/90">{children}</dd>
    </div>
  );
}

export default function HostDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: host, isLoading, isError, refetch } = useHost(id!);
  const { data: anomaly } = useHostAnomalyHistory(id!, '24h');
  const { data: hostAlerts } = useHostAlerts(id!);
  const { data: incidents } = useIncidents();
  const { data: graph } = useNetworkGraph();

  const hourly = useMemo(() => {
    const buckets = new Array(24).fill(0) as number[];
    const now = Date.now();
    for (const timestamp of anomaly?.timestamps ?? []) {
      const ts = timestamp < 1e12 ? timestamp * 1000 : timestamp;
      const hoursAgo = Math.floor((now - ts) / 3_600_000);
      if (hoursAgo >= 0 && hoursAgo < 24) buckets[23 - hoursAgo] += 1;
    }
    return buckets;
  }, [anomaly]);

  if (isLoading) return <HostDetailSkeleton />;

  if (isError || !host) {
    return (
      <div className="space-y-4">
        <BackLink />
        <div className="panel">
          <EmptyState
            icon={ServerOff}
            title={isError ? 'Asset could not be loaded' : 'Asset not found'}
            description={isError
              ? 'The console could not reach the inventory API for this host. Check the core service, then retry.'
              : 'This host is no longer in the inventory. It may have aged out of retention.'}
            action={(
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => navigate('/hosts')}>Back to assets</Button>
                {isError && <Button size="sm" onClick={() => refetch()}>Retry</Button>}
              </div>
            )}
          />
        </div>
      </div>
    );
  }

  const risk = riskValue(host.risk_score);
  const band = riskBand(host.risk_score);
  const riskLabel = RISK_LABEL[band];
  const hostIncidents = incidents?.filter((incident) => incident.entity === host.ip_address) ?? [];
  const openIncidents = hostIncidents.filter((incident) => incident.status !== 'resolved').length;
  const recentDetections = hostAlerts?.slice(0, 12) ?? [];
  const activityTotal = hourly.reduce((sum, value) => sum + value, 0);
  const activityPeak = Math.max(1, ...hourly);
  const graphNode = graph?.nodes.find((node) => node.ip === host.ip_address);
  const lastSeen = host.last_seen ? parseTimestamp(host.last_seen) : null;
  const firstSeen = host.created_at ? parseTimestamp(host.created_at) : null;

  const related = (graph?.edges ?? [])
    .filter((edge) => edge.src === host.ip_address || edge.dst === host.ip_address)
    .map((edge) => (edge.src === host.ip_address ? edge.dst : edge.src))
    .filter((ip: string, index: number, all: string[]) => all.indexOf(ip) === index)
    .slice(0, 10);

  const peerOf = (alert: Alert) => (alert.src_ip === host.ip_address ? alert.dst_ip : alert.src_ip);

  return (
    <div className="space-y-4">
      <BackLink />

      <PageHeader
        title={host.hostname || host.ip_address}
        meta={(
          <>
            {host.hostname && <span className="mono text-[11.5px] text-muted-foreground">{host.ip_address}</span>}
            <Badge variant={band} dot>{riskLabel} risk</Badge>
          </>
        )}
        description={[host.device_type ?? host.identity, host.group_name, host.os_info].filter(Boolean).join(' · ') || 'No role, group, or OS recorded.'}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Risk score" value={risk} hint={`${riskLabel} · 0-100`} tone={band} />
        <Metric label="Detections" value={host.alert_count} hint="last 24 hours" />
        <Metric
          label="Open incidents"
          value={incidents ? openIncidents : '—'}
          hint={incidents ? `${hostIncidents.length} linked` : 'loading incidents'}
        />
        <Metric
          label="First seen"
          value={firstSeen ? new Date(firstSeen).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
          hint="first observation"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card
            title="Recent detections"
            subtitle={hostAlerts ? `${hostAlerts.length} recorded for this asset` : 'Loading detections'}
            noPadding
          >
            {hostAlerts === undefined ? (
              <div className="p-4">
                {Array.from({ length: 5 }).map((_, index) => (
                  <div key={index} className="flex items-center gap-3 py-1.5">
                    <Skeleton className="h-1.5 w-1.5 rounded-full" />
                    <Skeleton className="h-3 w-32" />
                    <Skeleton className="ml-auto h-3 w-20" />
                    <Skeleton className="h-3 w-10" />
                  </div>
                ))}
              </div>
            ) : recentDetections.length ? (
              <div className="overflow-x-auto">
                <table className="table-shell">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Detection</th>
                      <th>Peer</th>
                      <th><span className="block text-right" title="Anomaly score">Score</span></th>
                      <th><span className="block text-right">Time</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentDetections.map((alert) => {
                      const peer = peerOf(alert);
                      const time = parseTimestamp(alert.timestamp);
                      return (
                        <tr key={alert.id}>
                          <td className={cn('border-l-2', SEVERITY_RAIL[alert.severity] ?? SEVERITY_RAIL.info)}>
                            <SeverityBadge severity={alert.severity} />
                          </td>
                          <td>
                            <Link
                              to={`/alerts/${alert.id}`}
                              className="text-[12px] font-medium text-foreground underline-offset-4 hover:text-primary hover:underline"
                            >
                              {alert.detection_type}
                            </Link>
                          </td>
                          <td><span className="mono text-[11.5px] text-muted-foreground">{peer ?? '—'}</span></td>
                          <td className="text-right"><span className="text-[12px] tabular-nums text-foreground/85">{alert.anomaly_score.toFixed(2)}</span></td>
                          <td className="text-right" title={new Date(time).toLocaleString()}>
                            <span className="text-[11.5px] text-muted-foreground">{relativeTime(time)}</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                icon={ShieldCheck}
                title="No detections recorded"
                description="This asset has not crossed the detection threshold in the retained window."
                className="py-10"
              />
            )}
          </Card>

          <Card
            title="Activity, 24 hours"
            subtitle="Anomaly events per hour"
            action={anomaly ? <span className="meta tabular-nums">{activityTotal} events</span> : undefined}
          >
            {anomaly === undefined ? (
              <Skeleton className="h-14 w-full" />
            ) : (
              <>
                <div
                  className="flex h-14 items-end gap-1"
                  role="img"
                  aria-label={`${activityTotal} anomaly events in the last 24 hours`}
                >
                  {hourly.map((count, index) => (
                    <div
                      key={index}
                      className="flex h-full flex-1 items-end"
                      title={`${count} events at ${new Date(Date.now() - (23 - index) * 3_600_000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`}
                    >
                      <div
                        className={cn('w-full rounded-[2px]', count ? 'bg-primary/70' : 'bg-muted')}
                        style={{ height: count ? `${Math.max(8, (count / activityPeak) * 100)}%` : '2px' }}
                      />
                    </div>
                  ))}
                </div>
                <div className="mt-1.5 flex justify-between text-[10.5px] text-muted-foreground">
                  <span>24h ago</span>
                  <span>now</span>
                </div>
              </>
            )}
          </Card>

          <Card title="Related entities" subtitle="Peers observed in the network graph">
            {related.length ? (
              <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                {related.map((ip) => {
                  const node = graph?.nodes.find((candidate) => candidate.ip === ip);
                  if (node && !node.external) {
                    return (
                      <Link
                        key={ip}
                        to={`/hosts/${node.id}`}
                        className="mono text-[11.5px] text-foreground underline-offset-4 hover:text-primary hover:underline"
                      >
                        {ip}
                      </Link>
                    );
                  }
                  return <span key={ip} className="mono text-[11.5px] text-muted-foreground">{ip}</span>;
                })}
              </div>
            ) : (
              <p className="text-[11.5px] text-muted-foreground">No peer relationships in the current window.</p>
            )}
          </Card>
        </div>

        <aside className="space-y-4">
          <Card title="Entity risk">
            <div className="flex justify-center py-1">
              <Gauge value={risk} size={140} label={`${riskLabel} risk`} />
            </div>
          </Card>

          <Card title="Identity">
            <dl className="space-y-2">
              <DetailsRow label="Address"><span className="mono text-[11.5px]">{host.ip_address}</span></DetailsRow>
              <DetailsRow label="Role">{host.device_type || '—'}</DetailsRow>
              <DetailsRow label="Group">{host.group_name || '—'}</DetailsRow>
              <DetailsRow label="OS">{host.os_info || '—'}</DetailsRow>
              <DetailsRow label="Identity">{host.identity || '—'}</DetailsRow>
              <DetailsRow label="Status">{host.status || '—'}</DetailsRow>
              <DetailsRow label="Baseline">{host.baseline_status || '—'}</DetailsRow>
              <DetailsRow label="Exposure">{graphNode ? (graphNode.external ? 'External' : 'Internal') : '—'}</DetailsRow>
              {graphNode?.vlan && <DetailsRow label="Segment">{graphNode.vlan}</DetailsRow>}
              <DetailsRow label="Last seen">
                <span title={lastSeen ? new Date(lastSeen).toLocaleString() : undefined}>
                  {lastSeen ? relativeTime(lastSeen) : '—'}
                </span>
              </DetailsRow>
            </dl>
          </Card>

          <Card title="Why this score">
            <p className="text-[11.5px] leading-[17px] text-muted-foreground">
              Risk is a 0-100 composite of anomaly deviation from the learned baseline, calibrated
              detection confidence, incident recurrence, and peer context.
            </p>
            {recentDetections.slice(0, 3).map((alert) => (
              <div key={alert.id} className="mt-3 border-t pt-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 items-center gap-1.5">
                    <SeverityBadge severity={alert.severity} withLabel={false} />
                    <span className="truncate text-[11.5px] font-medium text-foreground">{alert.detection_type}</span>
                  </span>
                  <span className="shrink-0 text-[10.5px] text-muted-foreground">
                    {relativeTime(parseTimestamp(alert.timestamp))}
                  </span>
                </div>
                {alert.reason && (
                  <p className="mt-1 line-clamp-2 text-[11px] leading-4 text-muted-foreground">{alert.reason}</p>
                )}
              </div>
            ))}
            {hostAlerts && !recentDetections.length && (
              <p className="mt-2 text-[11.5px] text-muted-foreground">No contributing detections recorded.</p>
            )}
          </Card>

          <Card title="Linked incidents" subtitle={incidents ? `${hostIncidents.length} on this asset` : 'Loading incidents'} noPadding>
            {incidents === undefined ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 3 }).map((_, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <Skeleton className="h-1.5 w-1.5 rounded-full" />
                    <Skeleton className="h-3 w-28" />
                    <Skeleton className="ml-auto h-3 w-8" />
                  </div>
                ))}
              </div>
            ) : hostIncidents.length ? (
              <ul className="divide-y">
                {hostIncidents.map((incident) => (
                  <li key={incident.id}>
                    <Link
                      to={`/incidents/${incident.id}`}
                      className="flex items-center gap-2.5 px-4 py-2 hover:bg-muted/50"
                    >
                      <SeverityBadge severity={incident.severity} withLabel={false} />
                      <span className="min-w-0 flex-1 truncate text-[12px] text-foreground">{displayFamily(incident.family)}</span>
                      <span className="text-[11px] tabular-nums text-muted-foreground">{incident.count}</span>
                      <span className="w-[46px] shrink-0 text-right text-[11px] text-muted-foreground">
                        {relativeTime(parseTimestamp(incident.last_seen))}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState
                icon={Inbox}
                title="No linked incidents"
                description="Detections on this asset have not been correlated into an incident."
                className="py-8"
              />
            )}
          </Card>
        </aside>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/hosts"
      className="inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft size={14} strokeWidth={1.5} />
      Assets
    </Link>
  );
}

function HostDetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-3.5 w-16" />
      <div className="space-y-2">
        <Skeleton className="h-5 w-56" />
        <Skeleton className="h-3.5 w-80" />
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-[86px] rounded-lg" />
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Skeleton className="h-64 rounded-lg" />
          <Skeleton className="h-32 rounded-lg" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-52 rounded-lg" />
          <Skeleton className="h-64 rounded-lg" />
        </div>
      </div>
    </div>
  );
}
