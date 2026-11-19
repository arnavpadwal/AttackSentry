import { useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Download, MoreHorizontal, RefreshCw, ScanLine, Search, ShieldCheck, Sparkles, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import EmptyState from '@/components/shared/EmptyState';
import PageHeader from '@/components/shared/PageHeader';
import { useAlerts, useUpdateAlertStatus } from '@/queries/alerts';
import { useBulkUpdateIncidents, useGenerateIncidentPlaybook, useIncidentSummary, useIncidents, useRequestMitigation, useUpdateIncidentStatus } from '@/queries/incidents';
import { displayFamily, parseTimestamp, relativeTime, cn } from '@/lib/utils';
import type { Incident } from '@/types';

type Tab = 'incidents' | 'alerts';

const severityDot: Record<string, string> = {
  critical: 'bg-severity-critical', high: 'bg-severity-high',
  medium: 'bg-severity-medium', low: 'bg-severity-low',
};
const severityRail: Record<string, string> = {
  critical: 'border-severity-critical', high: 'border-severity-high',
  medium: 'border-severity-medium', low: 'border-severity-low',
  info: 'border-severity-info',
};
const severityCounts = [
  { key: 'critical', label: 'critical' },
  { key: 'high', label: 'high' },
  { key: 'medium', label: 'medium' },
  { key: 'low', label: 'low' },
] as const;

const railClass = (severity: string) => severityRail[severity] ?? severityRail.info;
const absoluteTime = (value: string) => new Date(parseTimestamp(value)).toLocaleString();
const skeletonRows = [0, 1, 2, 3, 4, 5];

export default function ThreatFeedPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState<Tab>('incidents');
  const [severity, setSeverity] = useState(params.get('severity') ?? '');
  const [status, setStatus] = useState(params.get('status') ?? 'open');
  const [family, setFamily] = useState('');
  const [sort, setSort] = useState<'severity' | 'recent'>('severity');
  const [search, setSearch] = useState(params.get('q') ?? '');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [refreshing, setRefreshing] = useState(false);

  const { data: summary, refetch: refetchSummary } = useIncidentSummary();
  const { data: incidents, isLoading: incidentsLoading, isError: incidentsError, refetch: refetchIncidents } = useIncidents({
    status: status || undefined,
    severity: severity || undefined,
    family: family || undefined,
    q: search || undefined,
    sort,
    limit: 200,
  });
  const { data: alerts, isLoading: alertsLoading, isError: alertsError, refetch: refetchAlerts } = useAlerts({
    severity: severity || undefined,
    // Incident statuses and detection statuses share a control but not a vocabulary.
    status: status && status !== 'open' ? status : undefined,
    page: 1,
    page_size: 100,
  });
  const updateAlert = useUpdateAlertStatus();
  const updateIncident = useUpdateIncidentStatus();
  const bulkUpdate = useBulkUpdateIncidents();
  const mitigate = useRequestMitigation();
  const generatePlaybook = useGenerateIncidentPlaybook();

  const families = useMemo(() => Object.keys(summary?.by_family ?? {}).sort(), [summary]);
  const alertItems = useMemo(() => alerts?.items ?? [], [alerts]);
  const filteredAlerts = alertItems.filter((a) =>
    !search || a.detection_type.toLowerCase().includes(search.toLowerCase()) || (a.src_ip ?? '').includes(search)
  );
  const allSelected = Boolean(incidents?.length) && selected.size === incidents?.length;

  const openIncidents = summary?.open ?? 0;
  const newDetections = alertItems.filter((a) => a.status === 'new').length;
  const last24h = alertItems.filter((a) => parseTimestamp(a.timestamp) >= Date.now() - 86_400_000).length;

  const clearFilters = () => {
    setSeverity(''); setStatus('open'); setFamily(''); setSearch('');
    setParams({});
  };
  const hasFilters = Boolean(severity || family || search || (status && status !== 'open'));

  const refresh = async () => {
    setRefreshing(true);
    try {
      await Promise.all([refetchSummary(), refetchIncidents(), refetchAlerts()]);
    } finally {
      setRefreshing(false);
    }
  };

  const acknowledgeSelected = async () => {
    await bulkUpdate.mutateAsync({ ids: [...selected], status: 'acknowledged' });
    setSelected(new Set());
  };
  const resolveSelected = async () => {
    await bulkUpdate.mutateAsync({ ids: [...selected], status: 'resolved' });
    setSelected(new Set());
  };

  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-4">
        <PageHeader
          title="Detections"
          description={`${openIncidents} open incidents · ${newDetections} new detections · ${last24h} in last 24h`}
          actions={(
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() => window.open('/api/alerts/export?format=csv&range=all', '_blank')}
              >
                <Download size={14} strokeWidth={1.5} />Export
              </Button>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    size="icon"
                    variant="outline"
                    className="h-7 w-7"
                    onClick={refresh}
                    disabled={refreshing}
                    aria-label="Refresh detections"
                  >
                    <RefreshCw size={14} strokeWidth={1.5} className={cn(refreshing && 'animate-spin')} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Refresh</TooltipContent>
              </Tooltip>
            </>
          )}
        />

        <div className="panel flex flex-wrap items-center gap-x-5 gap-y-1 px-4 py-2">
          <span className="text-[11.5px] text-muted-foreground">Open by severity</span>
          {severityCounts.map((item) => (
            <span key={item.key} className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
              <span className={cn('h-1.5 w-1.5 rounded-full', severityDot[item.key])} aria-hidden />
              <span className="tabular-nums text-foreground">{summary?.by_severity?.[item.key] ?? 0}</span>
              {item.label}
            </span>
          ))}
        </div>

        <div className="panel flex flex-wrap items-center gap-2 px-3 py-2">
          <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
            <TabsList className="h-7">
              <TabsTrigger value="incidents" className="h-6 px-2.5 text-[11px]">Incidents <span className="ml-1 tabular-nums text-muted-foreground">{openIncidents}</span></TabsTrigger>
              <TabsTrigger value="alerts" className="h-6 px-2.5 text-[11px]">Detections <span className="ml-1 tabular-nums text-muted-foreground">{alerts?.total ?? 0}</span></TabsTrigger>
            </TabsList>
          </Tabs>
          <div className="relative min-w-[180px] flex-1 sm:max-w-[260px]">
            <Search size={14} strokeWidth={1.5} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Entity, family, or incident id" className="pl-8" />
          </div>
          <Select value={severity || 'all'} onValueChange={(v) => setSeverity(v === 'all' ? '' : v)}>
            <SelectTrigger className="h-8 w-[128px] text-[12px]"><SelectValue placeholder="Severity" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={status || 'all'} onValueChange={(v) => setStatus(v === 'all' ? '' : v)}>
            <SelectTrigger className="h-8 w-[128px] text-[12px]"><SelectValue placeholder="Status" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All status</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="acknowledged">Acknowledged</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
          {tab === 'incidents' && families.length > 0 && (
            <Select value={family || 'all'} onValueChange={(v) => setFamily(v === 'all' ? '' : v)}>
              <SelectTrigger className="h-8 w-[150px] text-[12px]"><SelectValue placeholder="Family" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All families</SelectItem>
                {families.map((item) => <SelectItem key={item} value={item}>{displayFamily(item)}</SelectItem>)}
              </SelectContent>
            </Select>
          )}
          {tab === 'incidents' && (
            <Select value={sort} onValueChange={(v) => setSort(v as 'severity' | 'recent')}>
              <SelectTrigger className="h-8 w-[118px] text-[12px]"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="severity">Priority</SelectItem><SelectItem value="recent">Most recent</SelectItem></SelectContent>
            </Select>
          )}
          {hasFilters && <Button variant="ghost" size="sm" onClick={clearFilters}><X size={14} strokeWidth={1.5} />Clear</Button>}
        </div>

        {tab === 'incidents' && selected.size > 0 && (
          <div className="panel flex flex-wrap items-center gap-2 border-primary/25 bg-primary/[0.04] px-3 py-2">
            <span className="text-[11.5px] font-medium tabular-nums">{selected.size} selected</span>
            <Button size="sm" variant="outline" onClick={acknowledgeSelected} disabled={bulkUpdate.isPending}>Acknowledge</Button>
            <Button size="sm" onClick={resolveSelected} disabled={bulkUpdate.isPending}>Resolve</Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
          </div>
        )}

        <div className="panel overflow-hidden">
          <div className="overflow-x-auto">
            {tab === 'incidents' ? (
              <table className="table-shell">
                <thead>
                  <tr>
                    <th className="w-9">
                      <input
                        aria-label="Select all incidents"
                        type="checkbox"
                        className="h-3.5 w-3.5 accent-primary"
                        checked={allSelected}
                        onChange={(e) => setSelected(e.target.checked ? new Set((incidents ?? []).map((i) => i.id)) : new Set())}
                      />
                    </th>
                    <th>Incident</th>
                    <th>Entity</th>
                    <th className="text-right">Detections</th>
                    <th className="text-right">First seen</th>
                    <th className="text-right">Last seen</th>
                    <th>Status</th>
                    <th className="w-10" />
                  </tr>
                </thead>
                <tbody>
                  {incidentsError ? (
                    <tr className="hover:bg-transparent">
                      <td colSpan={8} className="py-6!">
                        <div className="flex items-center justify-center gap-3 text-[12px] text-muted-foreground">
                          Could not load incidents.
                          <Button size="sm" variant="outline" onClick={() => refetchIncidents()}>Retry</Button>
                        </div>
                      </td>
                    </tr>
                  ) : incidentsLoading ? (
                    skeletonRows.map((row) => (
                      <tr key={row} className="hover:bg-transparent">
                        <td colSpan={8} className="p-0!"><Skeleton className="h-8 w-full rounded-none" /></td>
                      </tr>
                    ))
                  ) : incidents?.length ? incidents.map((incident) => (
                    <tr
                      key={incident.id}
                      data-selected={selected.has(incident.id) ? 'true' : undefined}
                      className="cursor-pointer"
                      onClick={() => navigate(`/incidents/${incident.id}`)}
                    >
                      <td className={cn('border-l-2 pl-3!', railClass(incident.severity))} onClick={(e) => e.stopPropagation()}>
                        <input
                          aria-label={`Select incident ${incident.id}`}
                          type="checkbox"
                          className="h-3.5 w-3.5 accent-primary"
                          checked={selected.has(incident.id)}
                          onChange={(e) => setSelected((current) => {
                            const next = new Set(current);
                            if (e.target.checked) next.add(incident.id); else next.delete(incident.id);
                            return next;
                          })}
                        />
                      </td>
                      <td>
                        <div className="min-w-0 max-w-[340px]">
                          <p className="truncate text-[12.5px] font-medium">{displayFamily(incident.family)}</p>
                          <p className="mono truncate text-[11.5px] text-muted-foreground">{incident.severity} · {incident.id}</p>
                        </div>
                      </td>
                      <td><div className="mono max-w-[180px] truncate text-[11.5px]">{incident.entity}</div></td>
                      <td className="text-right">
                        <p className="tabular-nums">{incident.count}</p>
                        <p className="text-[11px] tabular-nums text-muted-foreground">{Math.round(incident.peak_signal * 100)}% peak</p>
                      </td>
                      <td className="whitespace-nowrap text-right text-[11.5px] text-muted-foreground" title={absoluteTime(incident.created_at)}>
                        {relativeTime(parseTimestamp(incident.created_at))}
                      </td>
                      <td className="whitespace-nowrap text-right text-[11.5px] text-muted-foreground" title={absoluteTime(incident.last_seen)}>
                        {relativeTime(parseTimestamp(incident.last_seen))}
                      </td>
                      <td>
                        <span className={cn('text-[11.5px] capitalize', incident.status === 'open' ? 'text-foreground' : 'text-muted-foreground')}>
                          {incident.status}
                        </span>
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <IncidentActions
                          incident={incident}
                          generating={generatePlaybook.isPending}
                          onOpen={() => navigate(`/incidents/${incident.id}`)}
                          onGenerate={() => generatePlaybook.mutate(incident.id)}
                          onAcknowledge={() => updateIncident.mutate({ id: incident.id, status: 'acknowledged' })}
                          onMitigate={() => mitigate.mutate({
                            incident_id: incident.id,
                            action: recommendedAction(incident.family),
                            reason: `Containment requested for ${displayFamily(incident.family)}`,
                            ttl_minutes: 60,
                          })}
                          onResolve={() => updateIncident.mutate({ id: incident.id, status: 'resolved' })}
                        />
                      </td>
                    </tr>
                  )) : (
                    <tr className="hover:bg-transparent">
                      <td colSpan={8} className="p-0!">
                        <EmptyState
                          icon={ShieldCheck}
                          title="No incidents match these filters"
                          description="Widen severity, status, or the search to bring the queue back."
                          action={hasFilters ? <Button size="sm" variant="outline" onClick={clearFilters}>Clear filters</Button> : undefined}
                        />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            ) : (
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Detection</th>
                    <th>Source → destination</th>
                    <th className="text-right">Score</th>
                    <th>Entity</th>
                    <th className="text-right">Time</th>
                    <th className="text-right">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {alertsError ? (
                    <tr className="hover:bg-transparent">
                      <td colSpan={6} className="py-6!">
                        <div className="flex items-center justify-center gap-3 text-[12px] text-muted-foreground">
                          Could not load detections.
                          <Button size="sm" variant="outline" onClick={() => refetchAlerts()}>Retry</Button>
                        </div>
                      </td>
                    </tr>
                  ) : alertsLoading ? (
                    skeletonRows.map((row) => (
                      <tr key={row} className="hover:bg-transparent">
                        <td colSpan={6} className="p-0!"><Skeleton className="h-8 w-full rounded-none" /></td>
                      </tr>
                    ))
                  ) : filteredAlerts.length ? filteredAlerts.map((alert) => (
                    <tr key={alert.id} className="cursor-pointer" onClick={() => navigate(`/alerts/${alert.id}`)}>
                      <td className={cn('border-l-2 pl-3!', railClass(alert.severity))}>
                        <div className="min-w-0 max-w-[280px]">
                          <p className="truncate text-[12.5px] font-medium">{alert.detection_type}</p>
                          <p className="mono truncate text-[11.5px] text-muted-foreground">{alert.severity} · {alert.mitre_technique ?? '—'}</p>
                        </div>
                      </td>
                      <td className="mono whitespace-nowrap text-[11.5px]">
                        {alert.src_ip ?? '—'}
                        <span className="px-1.5 text-muted-foreground">→</span>
                        {alert.dst_ip ?? '—'}{alert.dst_port ? `:${alert.dst_port}` : ''}
                      </td>
                      <td className="text-right tabular-nums" title={`Confidence ${alert.confidence.toFixed(2)}`}>
                        {Math.round(Math.min(1, alert.confidence) * 100)}%
                      </td>
                      <td>
                        <div className="max-w-[180px] truncate text-[11.5px] text-muted-foreground">
                          {alert.group_name ?? alert.identity ?? alert.subnet ?? '—'}
                        </div>
                      </td>
                      <td className="whitespace-nowrap text-right text-[11.5px] text-muted-foreground" title={absoluteTime(alert.timestamp)}>
                        {relativeTime(parseTimestamp(alert.timestamp))}
                      </td>
                      <td className="text-right" onClick={(e) => e.stopPropagation()}>
                        <Select value={alert.status} onValueChange={(v) => updateAlert.mutate({ id: alert.id, status: v })}>
                          <SelectTrigger className="ml-auto h-7 w-[118px] text-[11px]"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="new">New</SelectItem>
                            <SelectItem value="acknowledged">Acknowledged</SelectItem>
                            <SelectItem value="resolved">Resolved</SelectItem>
                            <SelectItem value="false_positive">False positive</SelectItem>
                          </SelectContent>
                        </Select>
                      </td>
                    </tr>
                  )) : (
                    <tr className="hover:bg-transparent">
                      <td colSpan={6} className="p-0!">
                        <EmptyState
                          icon={ScanLine}
                          title="No detections match these filters"
                          description="Adjust severity, status, or the search to see more of the feed."
                          action={hasFilters ? <Button size="sm" variant="outline" onClick={clearFilters}>Clear filters</Button> : undefined}
                        />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}

function IncidentActions({ incident, generating, onOpen, onGenerate, onAcknowledge, onMitigate, onResolve }: {
  incident: Incident; generating: boolean; onOpen: () => void; onGenerate: () => void;
  onAcknowledge: () => void; onMitigate: () => void; onResolve: () => void;
}) {
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Incident actions">
              <MoreHorizontal size={14} strokeWidth={1.5} />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Incident actions</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuItem onClick={onOpen}>Open evidence</DropdownMenuItem>
        <DropdownMenuItem onClick={onGenerate} disabled={generating}><Sparkles size={13} strokeWidth={1.5} /> {generating ? 'Generating…' : 'Generate AI assessment'}</DropdownMenuItem>
        <DropdownMenuItem onClick={onAcknowledge} disabled={incident.status !== 'open'}>Acknowledge</DropdownMenuItem>
        <DropdownMenuItem onClick={onMitigate}>Request containment</DropdownMenuItem>
        <DropdownMenuItem onClick={onResolve} disabled={incident.status === 'resolved'}>Resolve incident</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function recommendedAction(family: string): 'isolate_host' | 'block_ip' | 'rate_limit' {
  const value = displayFamily(family).toLowerCase();
  if (value.includes('ddos') || value.includes('flood') || value.includes('denial')) return 'rate_limit';
  if (value.includes('brute') || value.includes('scan') || value.includes('recon')) return 'block_ip';
  return 'isolate_host';
}
