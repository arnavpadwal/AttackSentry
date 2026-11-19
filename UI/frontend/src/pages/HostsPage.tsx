import { useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Radar, Search, ServerOff } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import PageHeader from '@/components/shared/PageHeader';
import Metric from '@/components/shared/Metric';
import Card from '@/components/shared/Card';
import EmptyState from '@/components/shared/EmptyState';
import Button from '@/components/shared/Button';
import { useHosts } from '@/queries/hosts';
import { useIncidents } from '@/queries/incidents';
import { parseTimestamp, relativeTime, cn } from '@/lib/utils';

const RISK_FILTERS = [
  { value: 'all', label: 'All risk levels' },
  { value: 'critical', label: 'Critical (75+)' },
  { value: 'high', label: 'High (50-74)' },
  { value: 'medium', label: 'Medium (25-49)' },
  { value: 'low', label: 'Low (below 25)' },
] as const;

type RiskFilter = (typeof RISK_FILTERS)[number]['value'];
type RiskBand = Exclude<RiskFilter, 'all'>;

const RISK_BAR: Record<RiskBand, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
};

const RISK_RAIL: Record<RiskBand, string> = {
  critical: 'border-severity-critical',
  high: 'border-severity-high',
  medium: 'border-severity-medium',
  low: 'border-severity-low',
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

export default function HostsPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [search, setSearch] = useState(params.get('search') ?? '');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [roleFilter, setRoleFilter] = useState('all');

  const { data: hosts, isLoading, isError, refetch } = useHosts();
  const { data: incidents } = useIncidents({ limit: 500 });

  const hosted = useMemo(() => hosts ?? [], [hosts]);

  const roleOptions = useMemo(() => {
    const roles = hosted
      .map((host) => host.device_type ?? host.identity)
      .filter((role): role is string => Boolean(role));
    return Array.from(new Set(roles)).sort((a, b) => a.localeCompare(b));
  }, [hosted]);

  const detectionsByEntity = useMemo(() => {
    const counts = new Map<string, number>();
    for (const incident of incidents ?? []) {
      counts.set(incident.entity, (counts.get(incident.entity) ?? 0) + incident.count);
    }
    return counts;
  }, [incidents]);

  const filtered = useMemo(() => hosted.filter((host) => {
    const q = search.trim().toLowerCase();
    const matchesQuery = !q
      || host.ip_address.includes(q)
      || (host.hostname ?? '').toLowerCase().includes(q)
      || (host.group_name ?? '').toLowerCase().includes(q)
      || (host.identity ?? '').toLowerCase().includes(q);
    const matchesRisk = riskFilter === 'all' || riskBand(host.risk_score) === riskFilter;
    const role = host.device_type ?? host.identity ?? '';
    const matchesRole = roleFilter === 'all' || role === roleFilter;
    return matchesQuery && matchesRisk && matchesRole;
  }), [hosted, search, riskFilter, roleFilter]);

  const elevated = hosted.filter((host) => riskValue(host.risk_score) >= 50).length;
  const newIn24h = hosted.filter((host) => host.created_at && Date.now() - parseTimestamp(host.created_at) <= 86_400_000).length;
  const baselineActive = hosted.filter((host) => host.baseline_status === 'active').length;
  const learning = hosted.length - baselineActive;

  const pending = isLoading || isError;

  const clearFilters = () => {
    setSearch('');
    setRiskFilter('all');
    setRoleFilter('all');
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Assets"
        description="Every entity the sensor has attributed. Risk runs 0-100; elevated starts at 50."
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Monitored entities"
          value={pending ? '—' : hosted.length}
          hint="attributed by the sensor"
        />
        <Metric
          label="Elevated risk"
          value={pending ? '—' : elevated}
          hint="score 50 or higher"
          tone={elevated > 0 ? 'high' : 'default'}
        />
        <Metric
          label="New in 24h"
          value={pending ? '—' : newIn24h}
          hint="first observed in the last day"
        />
        <Metric
          label="Baseline active"
          value={pending ? '—' : baselineActive}
          hint={hosted.length === 0 ? 'no entities yet' : learning > 0 ? `${learning} still learning` : 'all entities learned'}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-0 flex-1 sm:max-w-xs">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="IP, hostname, group, identity"
            aria-label="Search assets"
            className="pl-8"
          />
        </div>
        <Select value={riskFilter} onValueChange={(value) => setRiskFilter(value as RiskFilter)}>
          <SelectTrigger aria-label="Filter by risk level" className="w-[148px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RISK_FILTERS.map((option) => (
              <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={roleFilter} onValueChange={setRoleFilter}>
          <SelectTrigger aria-label="Filter by role" className="w-[164px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All roles</SelectItem>
            {roleOptions.map((role) => (
              <SelectItem key={role} value={role}>{role}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card
        title="Observed assets"
        noPadding
        action={isLoading || isError ? undefined : (
          <span className="meta tabular-nums">{filtered.length} of {hosted.length}</span>
        )}
      >
        <div className="overflow-x-auto">
          <table className="table-shell">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Role / group</th>
                <th>OS</th>
                <th><span className="block text-right">Risk</span></th>
                <th><span className="block text-right">Detections</span></th>
                <th><span className="block text-right">Last seen</span></th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 6 }).map((_, index) => (
                  <tr key={index}>
                    <td><Skeleton className="h-3.5 w-40" /><Skeleton className="mt-1.5 h-2.5 w-24" /></td>
                    <td><Skeleton className="h-3 w-24" /><Skeleton className="mt-1.5 h-2.5 w-16" /></td>
                    <td><Skeleton className="h-3 w-20" /></td>
                    <td><div className="flex justify-end"><Skeleton className="h-1 w-12" /></div></td>
                    <td><div className="flex justify-end"><Skeleton className="h-3 w-6" /></div></td>
                    <td><div className="flex justify-end"><Skeleton className="h-3 w-14" /></div></td>
                  </tr>
                ))
              ) : isError ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={ServerOff}
                      title="Assets could not be loaded"
                      description="The console could not reach the inventory API. Check the core service, then retry."
                      action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
                    />
                  </td>
                </tr>
              ) : filtered.length ? (
                filtered.map((host) => {
                  const risk = riskValue(host.risk_score);
                  const band = riskBand(host.risk_score);
                  const detections = incidents ? (detectionsByEntity.get(host.ip_address) ?? 0) : null;
                  const lastSeen = host.last_seen ? parseTimestamp(host.last_seen) : null;

                  return (
                    <tr key={host.id}>
                      <td className={cn('border-l-2', RISK_RAIL[band])}>
                        <Link to={`/hosts/${host.id}`} className="block max-w-[280px]">
                          <span className={cn(
                            'block truncate text-[12.5px] text-foreground underline-offset-4 hover:text-primary hover:underline',
                            host.hostname && 'font-medium',
                            !host.hostname && 'mono',
                          )}>
                            {host.hostname || host.ip_address}
                          </span>
                          {host.hostname && (
                            <span className="mono block text-[11.5px] text-muted-foreground">{host.ip_address}</span>
                          )}
                        </Link>
                      </td>
                      <td>
                        <p className="truncate text-[12px] text-foreground">{host.device_type || host.identity || '—'}</p>
                        <p className="truncate text-[11px] text-muted-foreground">
                          {host.group_name || '—'}
                          {host.baseline_status !== 'active' && <span> · {host.baseline_status}</span>}
                        </p>
                      </td>
                      <td><span className="block max-w-[160px] truncate text-[11.5px] text-muted-foreground">{host.os_info || '—'}</span></td>
                      <td>
                        <div className="flex items-center justify-end gap-2" title={`Risk ${risk} of 100, ${band}`}>
                          <span className="h-1 w-12 overflow-hidden rounded-full bg-muted" aria-hidden>
                            <span className={cn('block h-full rounded-full', RISK_BAR[band])} style={{ width: `${risk}%` }} />
                          </span>
                          <span className="w-6 text-right text-[11px] tabular-nums text-foreground/85">{risk}</span>
                        </div>
                      </td>
                      <td className="text-right">
                        <span className={cn('text-[12px] tabular-nums', detections ? 'text-foreground/85' : 'text-muted-foreground')}>
                          {detections ?? '—'}
                        </span>
                      </td>
                      <td className="text-right" title={lastSeen ? new Date(lastSeen).toLocaleString() : undefined}>
                        <span className="text-[11.5px] text-muted-foreground">{lastSeen ? relativeTime(lastSeen) : '—'}</span>
                      </td>
                    </tr>
                  );
                })
              ) : hosted.length ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={Search}
                      title="No assets match these filters"
                      description="Adjust the search term, risk band, or role to widen the view."
                      action={<Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button>}
                    />
                  </td>
                </tr>
              ) : (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={Radar}
                      title="No assets under observation"
                      description="The sensor has not attributed a host yet. Start the sensor, then run a baseline so normal behaviour is learned before risk is scored."
                      action={<Button size="sm" variant="outline" onClick={() => navigate('/settings')}>Baseline settings</Button>}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
