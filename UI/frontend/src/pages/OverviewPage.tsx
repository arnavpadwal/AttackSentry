import { useNavigate } from 'react-router-dom';
import {
  Activity, ArrowRight, BrainCircuit, CheckCircle2, CircleAlert,
  RadioTower, Server, ShieldCheck, Siren, Users,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import Gauge from '@/components/shared/Gauge';
import TrafficWaves from '@/components/charts/TrafficWaves';
import { useSentryStatus, useTrafficSummary } from '@/queries/sentry';
import { useHosts } from '@/queries/hosts';
import { useIncidentSummary, useIncidents } from '@/queries/incidents';
import { useMitreCoverage } from '@/queries/network';
import { displayFamily, formatNumber, parseTimestamp, relativeTime, cn } from '@/lib/utils';

const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const severityDot: Record<string, string> = {
  critical: 'bg-severity-critical', high: 'bg-severity-high',
  medium: 'bg-severity-medium', low: 'bg-severity-low',
};

export default function OverviewPage() {
  const navigate = useNavigate();
  const { data: status } = useSentryStatus();
  const { data: traffic } = useTrafficSummary('24h');
  const { data: hosts } = useHosts();
  const { data: summary } = useIncidentSummary();
  const { data: incidents } = useIncidents({ status: 'open', sort: 'severity', limit: 8 });
  const { data: mitre } = useMitreCoverage();

  const priority = [...(incidents ?? [])]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || parseTimestamp(b.last_seen) - parseTimestamp(a.last_seen))
    .slice(0, 7);
  const critical = summary?.by_severity?.critical ?? 0;
  const atRisk = (hosts ?? []).filter((host) => host.risk_score >= 25).length;
  const topRisky = [...(hosts ?? [])].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);
  const threatScore = traffic?.threat_level ?? 0;
  const baselinePct = Math.round(status?.baseline_progress_pct ?? 0);
  const isActive = status?.mode === 'active';
  const severity = [
    { label: 'Critical', count: summary?.by_severity?.critical ?? 0, color: 'bg-severity-critical' },
    { label: 'High', count: summary?.by_severity?.high ?? 0, color: 'bg-severity-high' },
    { label: 'Medium', count: summary?.by_severity?.medium ?? 0, color: 'bg-severity-medium' },
    { label: 'Low', count: summary?.by_severity?.low ?? 0, color: 'bg-severity-low' },
  ];
  const severityTotal = severity.reduce((sum, item) => sum + item.count, 0);

  const kpis = [
    { label: 'Open incidents', value: summary?.open ?? 0, note: `${critical} critical`, icon: Siren, tone: critical > 0 ? 'text-severity-critical' : 'text-foreground' },
    { label: 'Entities at risk', value: atRisk, note: `${hosts?.length ?? 0} observed`, icon: Users },
    { label: 'Active sensors', value: traffic?.active_sensors ?? 0, note: 'checked in < 5 min', icon: RadioTower },
    { label: 'Flows analyzed', value: formatNumber(status?.flows_processed ?? 0), note: `${formatNumber(traffic?.total_flows_24h ?? 0)} in 24h`, icon: Activity },
    { label: 'Threat level', value: threatScore, note: threatScore >= 75 ? 'Elevated' : threatScore >= 40 ? 'Guarded' : 'Low', icon: ShieldCheck },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <h1 className="page-title">Security overview</h1>
          <p className="page-subtitle">Current posture, priority incidents, and detection health.</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={cn('gap-1.5 px-2 py-1', isActive ? 'border-primary/40 text-primary' : 'text-muted-foreground')}>
            <span className={cn('h-1.5 w-1.5 rounded-full', isActive ? 'live-dot bg-primary' : 'bg-severity-medium')} />
            {isActive ? 'Detection active' : `Baselining ${baselinePct}%`}
          </Badge>
          <Button size="sm" onClick={() => navigate('/threats')}>Open incident queue <ArrowRight size={14} /></Button>
        </div>
      </div>

      {critical > 0 && (
        <button onClick={() => navigate('/threats?severity=critical')} className="flex w-full items-center gap-3 rounded-md border border-severity-critical/30 bg-severity-critical/[0.07] px-4 py-2.5 text-left transition-colors hover:bg-severity-critical/10">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-severity-critical text-white"><Siren size={15} /></span>
          <span className="min-w-0 flex-1"><span className="block text-[13px] font-medium">{critical} critical {critical === 1 ? 'incident requires' : 'incidents require'} action</span><span className="block text-[11px] text-muted-foreground">Review evidence and containment guidance before the next shift.</span></span>
          <ArrowRight size={16} className="text-muted-foreground" />
        </button>
      )}

      <section className="panel grid grid-cols-2 divide-x divide-y overflow-hidden lg:grid-cols-5 lg:divide-y-0">
        {kpis.map((item) => (
          <div key={item.label} className="flex min-h-[92px] flex-col justify-between px-4 py-3">
            <div className="flex items-center justify-between">
              <span className="section-label">{item.label}</span>
              <item.icon size={14} className="text-muted-foreground/70" />
            </div>
            <div>
              <p className={cn('data-value text-[26px] font-semibold leading-8', item.tone)}>{item.value}</p>
              <p className="text-[11px] text-muted-foreground">{item.note}</p>
            </div>
          </div>
        ))}
      </section>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(300px,0.85fr)]">
        <section className="panel overflow-hidden">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Priority incidents</h2>
              <p className="text-[11px] text-muted-foreground">Ranked by severity and last observation</p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => navigate('/threats')}>View all <ArrowRight size={13} /></Button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b text-left">
                <th className="table-header-cell">Severity</th>
                <th className="table-header-cell">Entity</th>
                <th className="table-header-cell">Family</th>
                <th className="table-header-cell text-right">Signals</th>
                <th className="table-header-cell text-right">Last seen</th>
              </tr></thead>
              <tbody>
                {priority.length ? priority.map((incident) => (
                  <tr key={incident.id} className="row-hover cursor-pointer border-b last:border-0" onClick={() => navigate(`/incidents/${incident.id}`)}>
                    <td className="px-4 py-2.5"><span className="flex items-center gap-2 text-[11px] capitalize"><span className={cn('h-1.5 w-1.5 rounded-full', severityDot[incident.severity])} />{incident.severity}</span></td>
                    <td className="mono px-4 py-2.5 text-[12px]">{incident.entity}</td>
                    <td className="px-4 py-2.5 text-[12px]">{displayFamily(incident.family)}</td>
                    <td className="px-4 py-2.5 text-right text-[12px] tabular-nums">{incident.count}</td>
                    <td className="px-4 py-2.5 text-right text-[11px] text-muted-foreground">{relativeTime(parseTimestamp(incident.last_seen))}</td>
                  </tr>
                )) : (
                  <tr><td colSpan={5} className="px-4 py-12 text-center"><CheckCircle2 size={22} className="mx-auto mb-2 text-primary" /><p className="text-[13px] font-medium">No open incidents</p><p className="text-[11px] text-muted-foreground">Correlated detections will appear here.</p></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <div className="space-y-4">
          <section className="panel">
            <div className="panel-header"><h2 className="panel-title">Detection readiness</h2><Badge variant={isActive ? 'default' : 'secondary'}>{isActive ? 'Ready' : `${baselinePct}%`}</Badge></div>
            <div className="space-y-3 p-4">
              <div className="flex items-start gap-3">
                <BrainCircuit size={16} className="mt-0.5 text-primary" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between text-[12px]"><span className="font-medium">Behavior baseline</span><span className="text-muted-foreground">{isActive ? 'Active' : 'Learning'}</span></div>
                  <Progress value={isActive ? 100 : baselinePct} className="mt-2 h-1" />
                  <p className="mt-1.5 text-[11px] text-muted-foreground">{isActive ? 'Per-host and per-subnet models are enforcing.' : 'Collecting representative normal traffic.'}</p>
                </div>
              </div>
              <div className="flex items-start gap-3"><Server size={16} className="mt-0.5 text-muted-foreground" /><div><p className="text-[12px] font-medium">MoE attribution</p><p className="text-[11px] text-muted-foreground">Bundle {status?.moe_bundle_version || 'not loaded'}</p></div></div>
              <div className="flex items-start gap-3"><CircleAlert size={16} className={cn('mt-0.5', status?.llm_healthy ? 'text-primary' : 'text-muted-foreground')} /><div><p className="text-[12px] font-medium">AI triage</p><p className="text-[11px] text-muted-foreground">{status?.llm_healthy ? 'Provider available; batched per incident.' : 'Deterministic guidance active; provider offline.'}</p></div></div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header"><h2 className="panel-title">Open incidents by severity</h2><span className="text-[11px] text-muted-foreground">{severityTotal} total</span></div>
            <div className="space-y-3 p-4">
              {severity.map((item) => (
                <div key={item.label} className="grid grid-cols-[64px_1fr_28px] items-center gap-2 text-[11px]">
                  <span className="text-muted-foreground">{item.label}</span>
                  <span className="h-1.5 overflow-hidden rounded-full bg-muted"><span className={cn('block h-full rounded-full', item.color)} style={{ width: `${severityTotal ? Math.max(3, item.count / severityTotal * 100) : 0}%` }} /></span>
                  <span className="text-right font-medium tabular-nums">{item.count}</span>
                </div>
              ))}
              <div className="border-t pt-3"><div className="flex items-center justify-between text-[11px]"><span className="text-muted-foreground">Threat level</span><span className="font-medium">{threatScore}/100</span></div><Progress value={threatScore} className="mt-1.5 h-1" /></div>
            </div>
          </section>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(300px,0.85fr)]">
        <section className="panel">
          <div className="panel-header"><div><h2 className="panel-title">Network telemetry</h2><p className="text-[11px] text-muted-foreground">Inbound and outbound flow velocity</p></div><span className="flex items-center gap-1.5 text-[11px] text-primary"><span className="live-dot h-1.5 w-1.5 rounded-full bg-primary" />Live</span></div>
          <div className="p-4"><TrafficWaves height={180} /></div>
        </section>
        <section className="panel">
          <div className="panel-header"><h2 className="panel-title">MITRE ATT&amp;CK</h2><span className="text-[11px] text-muted-foreground">Observed tactics</span></div>
          <div className="space-y-3 p-4">
            {mitre?.tactics.length ? mitre.tactics.slice(0, 6).map((item) => (
              <div key={item.tactic}>
                <div className="flex justify-between text-[11px]"><span>{item.tactic}</span><span className="text-muted-foreground">{item.count} signals</span></div>
                <Progress value={Math.min(100, item.pct * 4)} className="mt-1.5 h-1" />
              </div>
            )) : <p className="py-8 text-center text-[12px] text-muted-foreground">Coverage populates after detections.</p>}
          </div>
        </section>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel">
          <div className="panel-header"><h2 className="panel-title">Highest-risk entities</h2><Button variant="ghost" size="sm" onClick={() => navigate('/hosts')}>Investigate <ArrowRight size={13} /></Button></div>
          <div>
            {topRisky.length ? topRisky.map((host) => (
              <button key={host.id} onClick={() => navigate(`/hosts/${host.id}`)} className="row-hover flex w-full items-center gap-3 border-t px-4 py-2.5 text-left first:border-0">
                <span className="mono flex h-7 w-7 items-center justify-center rounded bg-muted text-[11px] tabular-nums">{Math.round(host.risk_score)}</span>
                <span className="min-w-0 flex-1"><span className="block truncate text-[12px] font-medium">{host.hostname || host.ip_address}</span><span className="mono block truncate text-[11px] text-muted-foreground">{host.ip_address} · {host.group_name || 'Unassigned'}</span></span>
                <ArrowRight size={13} className="text-muted-foreground" />
              </button>
            )) : <p className="px-4 py-8 text-center text-[12px] text-muted-foreground">No entities discovered yet.</p>}
          </div>
        </section>
        <section className="panel">
          <div className="panel-header"><h2 className="panel-title">Top attack families</h2><span className="text-[11px] text-muted-foreground">Open cases</span></div>
          <div className="p-4">
            {summary?.by_family && Object.keys(summary.by_family).length ? (
              <div className="space-y-2.5">
                {Object.entries(summary.by_family).sort(([, a], [, b]) => b - a).slice(0, 6).map(([family, count]) => (
                  <div key={family} className="flex items-center justify-between gap-3 text-[12px]">
                    <span className="truncate">{displayFamily(family)}</span>
                    <span className="h-1.5 w-28 overflow-hidden rounded-full bg-muted"><span className="block h-full rounded-full bg-primary/70" style={{ width: `${Math.max(6, count / Math.max(1, summary.open) * 100)}%` }} /></span>
                    <span className="w-6 text-right tabular-nums text-muted-foreground">{count}</span>
                  </div>
                ))}
              </div>
            ) : <p className="py-8 text-center text-[12px] text-muted-foreground">No open families.</p>}
          </div>
        </section>
      </div>
    </div>
  );
}
