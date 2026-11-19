import { useNavigate } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Crosshair, Server } from 'lucide-react';
import PageHeader from '@/components/shared/PageHeader';
import Card from '@/components/shared/Card';
import Metric from '@/components/shared/Metric';
import Gauge from '@/components/shared/Gauge';
import SeverityBadge from '@/components/shared/SeverityBadge';
import EmptyState from '@/components/shared/EmptyState';
import TrafficWaves from '@/components/charts/TrafficWaves';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { useSentryStatus, useTrafficSummary } from '@/queries/sentry';
import { useHosts } from '@/queries/hosts';
import { useIncidentSummary, useIncidents } from '@/queries/incidents';
import { useMitreCoverage } from '@/queries/network';
import { displayFamily, formatBytes, formatNumber, parseTimestamp, relativeTime, cn } from '@/lib/utils';

const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const severityRail: Record<string, string> = {
  critical: 'border-severity-critical',
  high: 'border-severity-high',
  medium: 'border-severity-medium',
  low: 'border-severity-low',
};

function RowSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-8 w-full" />
      ))}
    </div>
  );
}

export default function OverviewPage() {
  const navigate = useNavigate();
  const { data: status, dataUpdatedAt } = useSentryStatus();
  const { data: traffic } = useTrafficSummary('24h');
  const { data: hosts, isLoading: hostsLoading } = useHosts();
  const { data: summary } = useIncidentSummary();
  const { data: incidents, isLoading: incidentsLoading } = useIncidents({ status: 'open', sort: 'severity', limit: 8 });
  const { data: mitre, isLoading: mitreLoading } = useMitreCoverage();

  const priority = [...(incidents ?? [])]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || parseTimestamp(b.last_seen) - parseTimestamp(a.last_seen))
    .slice(0, 7);
  const topRisky = [...(hosts ?? [])].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);
  const critical = summary?.by_severity?.critical ?? 0;
  const high = summary?.by_severity?.high ?? 0;
  const threatScore = traffic?.threat_level ?? 0;
  const baselinePct = Math.round(status?.baseline_progress_pct ?? 0);
  const isActive = status?.mode === 'active';

  const severity = [
    { key: 'critical', count: critical },
    { key: 'high', count: high },
    { key: 'medium', count: summary?.by_severity?.medium ?? 0 },
    { key: 'low', count: summary?.by_severity?.low ?? 0 },
  ];
  const severityTotal = severity.reduce((sum, item) => sum + item.count, 0);
  const severityWidth = (count: number) =>
    severityTotal ? Math.max(count > 0 ? 2 : 0, (count / severityTotal) * 100) : 0;
  const mitreMax = Math.max(1, ...(mitre?.tactics ?? []).map((item) => item.count));

  const engineLine = isActive ? 'Detection active' : status ? `Baselining ${baselinePct}%` : 'Connecting to engine';
  const threatLabel = threatScore >= 75 ? 'Elevated' : threatScore >= 40 ? 'Guarded' : 'Low';
  const worstHost = topRisky[0];
  const worstIncident = priority[0];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        description={`${engineLine} · ${hosts?.length ?? 0} entities monitored`}
        meta={
          <span className="text-[11.5px] tabular-nums text-muted-foreground">
            {dataUpdatedAt ? `updated ${relativeTime(dataUpdatedAt)}` : 'awaiting first poll'}
          </span>
        }
        actions={
          <Button size="sm" onClick={() => navigate('/threats')}>
            Incident queue <ArrowRight size={14} />
          </Button>
        }
      />

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-4">
        <Card
          title="Traffic"
          subtitle="Inbound and outbound flow velocity, rolling 60 seconds"
          noPadding
          action={
            <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <span className="live-dot h-1.5 w-1.5 rounded-full bg-primary" aria-hidden />
              Live
            </span>
          }
        >
          <TrafficWaves />
          <div className="grid grid-cols-3 divide-x border-t">
            {[
              { label: 'Active flows', value: traffic ? formatNumber(traffic.active_flows) : '—' },
              { label: 'Packets per second', value: traffic ? formatNumber(traffic.packets_per_sec) : '—' },
              { label: 'Bytes per second', value: traffic ? formatBytes(traffic.bytes_per_sec) : '—' },
            ].map((item) => (
              <div key={item.label} className="px-4 py-3">
                <p className="label">{item.label}</p>
                <p className="mt-1 text-[13px] tabular-nums text-foreground">{item.value}</p>
              </div>
            ))}
          </div>
        </Card>

          <div className="grid gap-3 sm:grid-cols-2">
            <Metric
              label="Detections, 24h"
              value={traffic ? formatNumber(traffic.total_alerts_24h) : '—'}
              hint={`${traffic?.critical_24h ?? 0} critical, ${traffic?.high_24h ?? 0} high`}
            />
            <Metric
              label="Open incidents"
              value={summary ? formatNumber(summary.open) : '—'}
              hint={`${summary?.acknowledged ?? 0} acknowledged`}
            />
            <Metric
              label="Critical and high"
              value={summary ? `${critical} / ${high}` : '—'}
              tone={critical > 0 ? 'critical' : high > 0 ? 'high' : 'default'}
              hint="Open incidents by severity"
            />
            <Metric
              label="Monitored entities"
              value={hosts ? formatNumber(hosts.length) : '—'}
              hint={`${traffic?.entities_at_risk ?? 0} at risk`}
            />
          </div>
        </div>

        <Card title="Posture" subtitle="Highest entity risk and worst open incident" noPadding>
          <div className="flex flex-col items-center border-b px-4 py-5">
            <Gauge
              value={threatScore}
              size={132}
              label="Threat level"
              sublabel={traffic ? threatLabel : 'Awaiting telemetry'}
            />
            <p className="mt-2 max-w-[32ch] text-center text-[11px] leading-4 text-muted-foreground">
              Composite of monitored entity risk and unresolved incident severity.
            </p>
          </div>
          <div className="divide-y">
            {worstHost ? (
              <button
                onClick={() => navigate(`/hosts/${worstHost.id}`)}
                className="row-hover flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
              >
                <span className="min-w-0">
                  <span className="block text-[11px] text-muted-foreground">Highest entity risk</span>
                  {worstHost.hostname ? (
                    <span className="mt-1 block truncate text-[12px]">{worstHost.hostname}</span>
                  ) : (
                    <span className="mono mt-1 block truncate text-[11.5px]">{worstHost.ip_address}</span>
                  )}
                </span>
                <span className="text-[13px] font-semibold tabular-nums">{Math.round(worstHost.risk_score)}</span>
              </button>
            ) : (
              <div className="px-4 py-3">
                <p className="label">Highest entity risk</p>
                <p className="mt-1 text-[12px] text-muted-foreground">
                  {hostsLoading ? 'Reading host table…' : 'No entity above baseline'}
                </p>
              </div>
            )}

            {worstIncident ? (
              <button
                onClick={() => navigate(`/incidents/${worstIncident.id}`)}
                className="row-hover flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
              >
                <span className="min-w-0">
                  <span className="block text-[11px] text-muted-foreground">Worst open incident</span>
                  <span className="mt-1 flex items-center gap-2">
                    <SeverityBadge severity={worstIncident.severity} />
                    <span className="mono truncate text-[11.5px] text-foreground">{worstIncident.entity}</span>
                  </span>
                  <span className="meta mt-1 block truncate">
                    {displayFamily(worstIncident.family)} · {worstIncident.count} signals
                  </span>
                </span>
                <ArrowRight size={13} className="shrink-0 text-muted-foreground" />
              </button>
            ) : (
              <div className="px-4 py-3">
                <p className="label">Worst open incident</p>
                <p className="mt-1 text-[12px] text-muted-foreground">
                  {incidentsLoading ? 'Reading incident queue…' : 'Nothing open'}
                </p>
              </div>
            )}

            {critical > 0 && (
              <button
                onClick={() => navigate('/threats?severity=critical')}
                className="row-hover flex w-full items-center gap-2 px-4 py-3 text-left"
              >
                <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-severity-critical" aria-hidden />
                <span className="flex-1 text-[12px]">
                  {critical} critical {critical === 1 ? 'incident needs' : 'incidents need'} action
                </span>
                <ArrowRight size={13} className="shrink-0 text-muted-foreground" />
              </button>
            )}

            <div className="px-4 py-3">
              <p className="label">Engine</p>
              <p className="mt-1 flex items-center gap-1.5 text-[12px]">
                <span className={cn('h-1.5 w-1.5 rounded-full', isActive ? 'bg-primary' : 'bg-severity-medium')} aria-hidden />
                {engineLine}
              </p>
              <p className="meta mt-1 truncate">
                Bundle {status?.moe_bundle_version || 'not loaded'} · AI triage {status?.llm_healthy ? 'available' : 'offline'}
              </p>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(260px,0.8fr)_minmax(0,1.6fr)]">
        <Card title="Open by severity" subtitle={`${severityTotal} unresolved`}>
          <div className="space-y-3">
            {severity.map((item) => (
              <div key={item.key}>
                <div className="flex items-baseline justify-between gap-3">
                  <SeverityBadge severity={item.key} />
                  <span className="text-[12.5px] tabular-nums text-foreground">{item.count}</span>
                </div>
                <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-foreground/20"
                    style={{ width: `${severityWidth(item.count)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card
          title="Highest-risk entities"
          subtitle="Ranked by current risk score"
          noPadding
          action={
            <Button variant="ghost" size="sm" onClick={() => navigate('/hosts')}>
              All entities <ArrowRight size={13} />
            </Button>
          }
        >
          {hostsLoading ? (
            <RowSkeleton rows={5} />
          ) : topRisky.length ? (
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Entity</th>
                    <th>Address</th>
                    <th>Group</th>
                    <th className="text-right">Risk</th>
                    <th className="text-right">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisky.map((host) => (
                    <tr key={host.id} className="cursor-pointer" onClick={() => navigate(`/hosts/${host.id}`)}>
                      <td className="text-[12.5px] font-medium">{host.hostname || host.ip_address}</td>
                      <td><span className="mono text-[11.5px]">{host.ip_address}</span></td>
                      <td className="text-[11.5px] text-muted-foreground">{host.group_name || 'Unassigned'}</td>
                      <td className="text-right tabular-nums">{Math.round(host.risk_score)}</td>
                      <td className="text-right text-[11.5px] text-muted-foreground">
                        {host.last_seen ? relativeTime(parseTimestamp(host.last_seen)) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={Server}
              title="No entities observed"
              description="Entities appear after the sensor sees their first flows."
              className="py-10"
            />
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(260px,0.8fr)]">
        <Card
          title="Priority incidents"
          subtitle="Ranked by severity, then last observation"
          noPadding
          action={
            <Button variant="ghost" size="sm" onClick={() => navigate('/threats')}>
              Queue <ArrowRight size={13} />
            </Button>
          }
        >
          {incidentsLoading ? (
            <RowSkeleton rows={5} />
          ) : priority.length ? (
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Entity</th>
                    <th>Family</th>
                    <th className="text-right">Signals</th>
                    <th className="text-right">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {priority.map((incident) => (
                    <tr key={incident.id} className="cursor-pointer" onClick={() => navigate(`/incidents/${incident.id}`)}>
                      <td>
                        <span
                          className={cn(
                            'flex items-center border-l-2 pl-3 text-[11.5px] capitalize',
                            severityRail[incident.severity] ?? 'border-transparent',
                          )}
                        >
                          {incident.severity}
                        </span>
                      </td>
                      <td><span className="mono text-[11.5px]">{incident.entity}</span></td>
                      <td className="text-[11.5px] text-muted-foreground">{displayFamily(incident.family)}</td>
                      <td className="text-right tabular-nums">{incident.count}</td>
                      <td className="text-right text-[11.5px] text-muted-foreground">
                        {relativeTime(parseTimestamp(incident.last_seen))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={CheckCircle2}
              title="No open incidents"
              description="Correlated detections appear here once a family crosses its threshold."
              className="py-10"
            />
          )}
        </Card>

        <Card
          title="MITRE ATT&CK"
          subtitle={mitre ? `${mitre.total} signals mapped` : 'Awaiting detections'}
          noPadding
        >
          {mitreLoading ? (
            <RowSkeleton rows={5} />
          ) : mitre?.tactics.length ? (
            <div className="space-y-3 p-4">
              {mitre.tactics.slice(0, 6).map((item) => (
                <div key={item.tactic}>
                  <div className="flex items-baseline justify-between gap-3 text-[12px]">
                    <span className="truncate">{item.tactic}</span>
                    <span className="tabular-nums text-muted-foreground">{item.count}</span>
                  </div>
                  <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-foreground/20"
                      style={{ width: `${(item.count / mitreMax) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={Crosshair}
              title="No tactics mapped"
              description="Tactics appear as detections carry ATT&CK labels."
              className="py-10"
            />
          )}
        </Card>
      </div>
    </div>
  );
}
