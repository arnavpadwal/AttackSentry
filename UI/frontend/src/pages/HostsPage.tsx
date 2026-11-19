import { useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Search, Monitor } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useHosts } from '@/queries/hosts';
import { parseTimestamp, relativeTime, cn } from '@/lib/utils';

export default function HostsPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [search, setSearch] = useState(params.get('search') ?? '');
  const { data: hosts, isLoading } = useHosts();

  const filtered = useMemo(() => (hosts ?? []).filter((host) => {
    const q = search.trim().toLowerCase();
    return !q || host.ip_address.includes(q) || (host.hostname ?? '').toLowerCase().includes(q) || (host.group_name ?? '').toLowerCase().includes(q) || (host.identity ?? '').toLowerCase().includes(q);
  }), [hosts, search]);

  return (
    <div className="space-y-4">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div><h1 className="page-title">Assets & entities</h1><p className="page-subtitle">Every observed host, its identity, and current risk posture.</p></div>
        <div className="relative w-full sm:w-64"><Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" /><Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="IP, hostname, group, identity" className="pl-8" /></div>
      </div>

      <section className="panel overflow-hidden">
        <div className="panel-header"><h2 className="panel-title">Observed entities</h2><Badge variant="outline">{filtered.length} hosts</Badge></div>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader><TableRow className="hover:bg-transparent"><TableHead>Host</TableHead><TableHead>IP address</TableHead><TableHead>Group</TableHead><TableHead>Identity</TableHead><TableHead>Baseline</TableHead><TableHead className="text-right">Last seen</TableHead><TableHead className="text-right">Risk</TableHead></TableRow></TableHeader>
            <TableBody>
              {isLoading ? <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">Loading entities…</TableCell></TableRow>
                : filtered.length ? filtered.map((host) => (
                  <TableRow key={host.id} className="cursor-pointer" onClick={() => navigate(`/hosts/${host.id}`)}>
                    <TableCell><div className="flex items-center gap-2"><span className="flex h-6 w-6 items-center justify-center rounded bg-muted"><Monitor size={12} className="text-muted-foreground" /></span><span className="text-[12px] font-medium">{host.hostname || 'Unnamed host'}</span></div></TableCell>
                    <TableCell className="mono text-[11px]">{host.ip_address}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{host.group_name ?? '—'}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{host.identity ?? '—'}</TableCell>
                    <TableCell><Badge variant={host.baseline_status === 'active' ? 'default' : 'secondary'} className="capitalize">{host.baseline_status}</Badge></TableCell>
                    <TableCell className="text-right text-[11px] text-muted-foreground">{host.last_seen ? relativeTime(parseTimestamp(host.last_seen)) : '—'}</TableCell>
                    <TableCell className="text-right"><span className={cn('inline-flex min-w-8 justify-center rounded-sm px-1.5 py-0.5 text-[11px] font-semibold tabular-nums', host.risk_score >= 70 ? 'bg-severity-critical/15 text-severity-critical' : host.risk_score >= 35 ? 'bg-severity-medium/15 text-severity-medium' : 'bg-muted text-muted-foreground')}>{Math.round(host.risk_score)}</span></TableCell>
                  </TableRow>
                )) : <TableRow><TableCell colSpan={7} className="py-12 text-center text-[12px] text-muted-foreground">No entities discovered yet.</TableCell></TableRow>}
            </TableBody>
          </Table>
        </div>
      </section>
    </div>
  );
}
