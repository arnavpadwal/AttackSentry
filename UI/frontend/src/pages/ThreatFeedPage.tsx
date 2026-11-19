import { useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useAlerts, useUpdateAlertStatus } from '@/queries/alerts';
import { useBulkUpdateIncidents, useGenerateIncidentPlaybook, useIncidentSummary, useIncidents, useRequestMitigation, useUpdateIncidentStatus } from '@/queries/incidents';
import { Download, MoreHorizontal, Sparkles, Search, ShieldCheck, X } from 'lucide-react';
import { displayFamily, parseTimestamp, relativeTime, cn } from '@/lib/utils';
import type { Incident } from '@/types';

type Tab = 'incidents' | 'alerts';
const severityVariant = (s: string) => s === 'critical' ? 'destructive' : s === 'high' ? 'default' : s === 'medium' ? 'secondary' : 'muted';
const severityDot: Record<string, string> = {
  critical: 'bg-severity-critical', high: 'bg-severity-high',
  medium: 'bg-severity-medium', low: 'bg-severity-low',
};

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

  const { data: summary } = useIncidentSummary();
  const { data: incidents, isLoading: incidentsLoading } = useIncidents({
    status: status || undefined,
    severity: severity || undefined,
    family: family || undefined,
    q: search || undefined,
    sort,
    limit: 200,
  });
  const { data: alerts, isLoading: alertsLoading } = useAlerts({
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
  const filteredAlerts = (alerts?.items ?? []).filter((a) =>
    !search || a.detection_type.toLowerCase().includes(search.toLowerCase()) || (a.src_ip ?? '').includes(search)
  );
  const allSelected = Boolean(incidents?.length) && selected.size === incidents?.length;

  const clearFilters = () => {
    setSeverity(''); setStatus('open'); setFamily(''); setSearch('');
    setParams({});
  };
  const hasFilters = Boolean(severity || family || search || (status && status !== 'open'));

  return (
    <div className="space-y-4">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <h1 className="page-title">Incident queue</h1>
          <p className="page-subtitle">Correlated cases ranked for triage, ownership, and containment.</p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />{summary?.open ?? 0} open</span>
          <span className="text-border">·</span>
          <span>{summary?.by_severity?.critical ?? 0} critical</span>
          <span className="text-border">·</span>
          <span>{summary?.total ?? 0} total</span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-card p-2">
        <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
          <TabsList className="h-7">
            <TabsTrigger value="incidents" className="h-6 px-2.5 text-[11px]">Incidents <span className="ml-1 tabular-nums text-muted-foreground">{summary?.open ?? 0}</span></TabsTrigger>
            <TabsTrigger value="alerts" className="h-6 px-2.5 text-[11px]">Detections <span className="ml-1 tabular-nums text-muted-foreground">{alerts?.total ?? 0}</span></TabsTrigger>
          </TabsList>
        </Tabs>
        <div className="relative min-w-[180px] flex-1 sm:max-w-[280px]">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Entity, family, incident ID" className="pl-8" />
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
        {hasFilters && <Button variant="ghost" size="sm" onClick={clearFilters}><X size={13} /> Clear</Button>}
        <div className="ml-auto flex items-center gap-1.5">
          {selected.size > 0 && tab === 'incidents' && (
            <div className="flex items-center gap-1.5 rounded border bg-muted/50 px-2 py-1">
              <span className="text-[11px] font-medium">{selected.size} selected</span>
              <Button size="sm" variant="outline" onClick={async () => { await bulkUpdate.mutateAsync({ ids: [...selected], status: 'acknowledged' }); setSelected(new Set()); }}>Acknowledge</Button>
              <Button size="sm" onClick={async () => { await bulkUpdate.mutateAsync({ ids: [...selected], status: 'resolved' }); setSelected(new Set()); }}>Resolve</Button>
            </div>
          )}
          <Button size="sm" variant="outline" onClick={() => window.open('/api/alerts/export?format=csv&range=all', '_blank')}><Download size={13} /> Export</Button>
        </div>
      </div>

      <div className="panel overflow-hidden">
        {tab === 'incidents' ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-9"><input aria-label="Select all incidents" type="checkbox" checked={allSelected} onChange={(e) => setSelected(e.target.checked ? new Set((incidents ?? []).map((i) => i.id)) : new Set())} /></TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Entity</TableHead>
                  <TableHead>Family</TableHead>
                  <TableHead className="text-right">Signals</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead className="text-right">Last seen</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidentsLoading ? (
                  <TableRow><TableCell colSpan={9} className="py-10 text-center text-muted-foreground">Loading incidents…</TableCell></TableRow>
                ) : incidents?.length ? incidents.map((i) => (
                  <IncidentRow
                    key={i.id}
                    incident={i}
                    selected={selected.has(i.id)}
                    onSelect={(checked) => setSelected((current) => { const next = new Set(current); if (checked) next.add(i.id); else next.delete(i.id); return next; })}
                    onOpen={() => navigate(`/incidents/${i.id}`)}
                    onGenerate={() => generatePlaybook.mutate(i.id)}
                    onMitigate={() => mitigate.mutate({ incident_id: i.id, action: recommendedAction(i.family), reason: `Containment requested for ${displayFamily(i.family)}`, ttl_minutes: 60 })}
                    onResolve={() => updateIncident.mutate({ id: i.id, status: 'resolved' })}
                    onAcknowledge={() => updateIncident.mutate({ id: i.id, status: 'acknowledged' })}
                    generating={generatePlaybook.isPending}
                  />
                )) : (
                  <TableRow><TableCell colSpan={9} className="py-14 text-center"><ShieldCheck size={22} className="mx-auto mb-2 text-primary" /><p className="text-[13px] font-medium">No incidents match these filters</p><p className="mt-1 text-[11px] text-muted-foreground">Adjust severity, status, or search terms.</p></TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Severity</TableHead>
                  <TableHead>Detection</TableHead>
                  <TableHead>Entity</TableHead>
                  <TableHead>MITRE</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead className="text-right">Time</TableHead>
                  <TableHead className="text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alertsLoading ? (
                  <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">Loading detections…</TableCell></TableRow>
                ) : filteredAlerts.length ? filteredAlerts.map((a) => (
                  <TableRow key={a.id} className="cursor-pointer" onClick={() => navigate(`/alerts/${a.id}`)}>
                    <TableCell><Badge variant={severityVariant(a.severity)} className="capitalize">{a.severity}</Badge></TableCell>
                    <TableCell className="max-w-[260px] truncate text-[12px] font-medium">{a.detection_type}</TableCell>
                    <TableCell className="mono text-[11px]">{a.src_ip}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{a.mitre_technique ?? '—'}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="h-1 w-12 overflow-hidden rounded-full bg-secondary"><span className="block h-full rounded-full bg-primary" style={{ width: `${Math.min(100, a.confidence * 100)}%` }} /></span>
                        <span className="text-[11px] tabular-nums">{Math.round(a.confidence * 100)}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right text-[11px] text-muted-foreground">{relativeTime(parseTimestamp(a.timestamp))}</TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      <Select value={a.status} onValueChange={(v) => updateAlert.mutate({ id: a.id, status: v })}>
                        <SelectTrigger className="ml-auto h-7 w-[118px] text-[11px]"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="new">New</SelectItem>
                          <SelectItem value="acknowledged">Acknowledged</SelectItem>
                          <SelectItem value="resolved">Resolved</SelectItem>
                          <SelectItem value="false_positive">False positive</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                )) : (
                  <TableRow><TableCell colSpan={7} className="py-14 text-center text-muted-foreground">No detections match these filters</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}

function IncidentRow({ incident, selected, onSelect, onOpen, onGenerate, onMitigate, onResolve, onAcknowledge, generating }: {
  incident: Incident; selected: boolean; onSelect: (checked: boolean) => void; onOpen: () => void;
  onGenerate: () => void; onMitigate: () => void; onResolve: () => void; onAcknowledge: () => void; generating: boolean;
}) {
  return (
    <TableRow className="cursor-pointer" onClick={onOpen}>
      <TableCell onClick={(e) => e.stopPropagation()}><input aria-label={`Select incident ${incident.id}`} type="checkbox" checked={selected} onChange={(e) => onSelect(e.target.checked)} /></TableCell>
      <TableCell><span className="flex items-center gap-2 text-[11px] capitalize"><span className={cn('h-1.5 w-1.5 rounded-full', severityDot[incident.severity])} />{incident.severity}</span></TableCell>
      <TableCell className="mono text-[11px]">{incident.entity}</TableCell>
      <TableCell className="text-[12px]">{displayFamily(incident.family)}</TableCell>
      <TableCell className="text-right text-[12px] tabular-nums">{incident.count}</TableCell>
      <TableCell className="text-[11px] tabular-nums">{Math.round(incident.peak_signal * 100)}%</TableCell>
      <TableCell className="text-right text-[11px] text-muted-foreground">{relativeTime(parseTimestamp(incident.last_seen))}</TableCell>
      <TableCell><Badge variant={incident.status === 'open' ? 'outline' : 'secondary'} className="capitalize">{incident.status}</Badge></TableCell>
      <TableCell onClick={(e) => e.stopPropagation()}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Incident actions"><MoreHorizontal size={14} /></Button></DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem onClick={onOpen}>Open evidence</DropdownMenuItem>
            <DropdownMenuItem onClick={onGenerate} disabled={generating}><Sparkles size={13} /> {generating ? 'Generating…' : 'Generate AI assessment'}</DropdownMenuItem>
            <DropdownMenuItem onClick={onAcknowledge} disabled={incident.status !== 'open'}>Acknowledge</DropdownMenuItem>
            <DropdownMenuItem onClick={onMitigate}>Request containment</DropdownMenuItem>
            <DropdownMenuItem onClick={onResolve} disabled={incident.status === 'resolved'}>Resolve incident</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );
}

function recommendedAction(family: string): 'isolate_host' | 'block_ip' | 'rate_limit' {
  const value = displayFamily(family).toLowerCase();
  if (value.includes('ddos') || value.includes('flood') || value.includes('denial')) return 'rate_limit';
  if (value.includes('brute') || value.includes('scan') || value.includes('recon')) return 'block_ip';
  return 'isolate_host';
}
