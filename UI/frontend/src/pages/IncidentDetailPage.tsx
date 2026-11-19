import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, CheckCircle2, Clock3, Crosshair, ShieldAlert, ShieldOff, Sparkles } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useGenerateIncidentPlaybook, useIncident, useIncidentAlerts, useIncidentPlaybook, useRequestMitigation, useUpdateIncidentStatus } from '@/queries/incidents';
import { cn, displayFamily, parseTimestamp, relativeTime } from '@/lib/utils';
import { useAuthStore } from '@/stores';

const severityDot: Record<string, string> = {
  critical: 'bg-severity-critical', high: 'bg-severity-high',
  medium: 'bg-severity-medium', low: 'bg-severity-low',
};

export default function IncidentDetailPage() {
  const { id = '' } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: incident, isLoading } = useIncident(id);
  const { data: alerts } = useIncidentAlerts(id);
  const { data: playbook } = useIncidentPlaybook(id);
  const generatePlaybook = useGenerateIncidentPlaybook();
  const update = useUpdateIncidentStatus();
  const requestMitigation = useRequestMitigation();
  const role = useAuthStore((state) => state.user?.role);

  if (isLoading) return <div className="space-y-4"><Skeleton className="h-9 w-64" /><Skeleton className="h-72 w-full" /></div>;
  if (!incident) return <div className="panel p-10 text-center"><p className="text-[13px] font-medium">Incident not found</p><Button variant="link" onClick={() => navigate('/threats')}>Return to queue</Button></div>;

  const active = incident.status !== 'resolved';
  const sourceEntities = [...new Set((alerts ?? []).map((alert) => alert.src_ip).filter(Boolean))] as string[];
  const recommended = recommendedAction(incident.family);
  const evidence = (alerts ?? []).slice(0, 50);
  const frameworks = evidence[0]?.frameworks;

  return (
    <div className="space-y-4">
      <button onClick={() => navigate(-1)} className="flex items-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground"><ArrowLeft size={13} /> Back to incident queue</button>

      <section className="panel">
        <div className="flex flex-col gap-4 p-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={incident.severity === 'critical' ? 'destructive' : 'secondary'} className="gap-1.5 capitalize"><span className={cn('h-1.5 w-1.5 rounded-full', severityDot[incident.severity])} />{incident.severity}</Badge>
              <Badge variant="outline" className="capitalize">{incident.status}</Badge>
              <span className="mono text-[10px] text-muted-foreground">{incident.id}</span>
            </div>
            <h1 className="mt-2 text-xl font-semibold tracking-tight">{displayFamily(incident.family)}</h1>
            <p className="mt-1 text-[12px] text-muted-foreground">Affected entity <span className="mono text-foreground">{incident.entity}</span> · {incident.count} correlated signals</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="outline" disabled={generatePlaybook.isPending} onClick={() => generatePlaybook.mutate(id)}><Sparkles size={13} /> {generatePlaybook.isPending ? 'Generating…' : 'AI assessment'}</Button>
            {active && role !== 'viewer' && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild><Button size="sm" variant="outline"><ShieldOff size={13} /> Containment</Button></DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuItem onClick={() => requestMitigation.mutate({ incident_id: id, action: recommended, reason: `Attack-aware ${recommended.replace(/_/g, ' ')} requested from incident ${id}`, ttl_minutes: 60 })}>
                    Apply {recommended.replace(/_/g, ' ')} on {incident.entity}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => requestMitigation.mutate({ incident_id: id, action: 'isolate_host', reason: `Host isolation requested from incident ${id}`, ttl_minutes: 60 })}>
                    Isolate host
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => requestMitigation.mutate({ incident_id: id, action: 'block_ip', reason: `Source block requested from incident ${id}`, ttl_minutes: 60 })}>
                    Block source IP
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
            {active && incident.status === 'open' && <Button size="sm" variant="outline" onClick={() => update.mutate({ id, status: 'acknowledged' })}>Acknowledge</Button>}
            {active ? <Button size="sm" onClick={() => update.mutate({ id, status: 'resolved' })}><CheckCircle2 size={13} /> Resolve</Button> : <Button size="sm" variant="outline" onClick={() => update.mutate({ id, status: 'open' })}>Reopen</Button>}
          </div>
        </div>
        <div className="grid grid-cols-2 border-t sm:grid-cols-4">
          {[
            ['Correlated signals', incident.count],
            ['Peak confidence', `${Math.round(incident.peak_signal * 100)}%`],
            ['First observed', relativeTime(parseTimestamp(incident.created_at))],
            ['Last activity', relativeTime(parseTimestamp(incident.last_seen))],
          ].map(([label, value]) => (
            <div key={label} className="border-r px-4 py-2.5 last:border-r-0">
              <p className="section-label">{label}</p><p className="mt-0.5 text-[13px] font-semibold tabular-nums">{value}</p>
            </div>
          ))}
        </div>
      </section>

      {sourceEntities.length > 1 && (
        <section className="panel px-4 py-3">
          <p className="section-label">Distributed sources · {sourceEntities.length}</p>
          <div className="mt-2 flex flex-wrap gap-1.5">{sourceEntities.slice(0, 40).map((ip) => <Badge key={ip} variant="outline" className="mono text-[10px]">{ip}</Badge>)}</div>
        </section>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.65fr)]">
        <div className="space-y-4">
          <section className="panel">
            <div className="panel-header"><div className="flex items-center gap-2"><Sparkles size={14} className="text-primary" /><h2 className="panel-title">AI assessment</h2></div>{playbook?.is_fallback && <Badge variant="outline">Deterministic guidance</Badge>}</div>
            <div className="p-4">
              {playbook ? (
                <div className="space-y-2">
                  <p className="text-[13px] leading-6">{playbook.attack_summary}</p>
                  {playbook.technical_analysis && <p className="text-[12px] leading-6 text-muted-foreground">{playbook.technical_analysis}</p>}
                  <div className="flex flex-wrap gap-2 pt-1"><Badge variant="secondary">Severity {playbook.severity}</Badge><Badge variant="outline">Confidence {playbook.confidence}</Badge>{playbook.is_fallback && <Badge variant="outline">Provider offline — fallback</Badge>}</div>
                </div>
              ) : (
                <div className="flex items-start gap-3">
                  <ShieldAlert size={16} className="mt-0.5 text-muted-foreground" />
                  <div><p className="text-[12px] font-medium">No assessment yet</p><p className="mt-1 text-[11px] text-muted-foreground">The first assessment runs automatically after an incident is created. Generate one now to retry.</p><Button size="sm" className="mt-2" disabled={generatePlaybook.isPending} onClick={() => generatePlaybook.mutate(id)}><Sparkles size={13} /> Generate assessment</Button></div>
                </div>
              )}
            </div>
          </section>

          <section className="panel overflow-hidden">
            <div className="panel-header"><h2 className="panel-title">Correlated evidence</h2><span className="text-[11px] text-muted-foreground">{evidence.length} of {alerts?.length ?? 0} records</span></div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead><tr className="border-b text-left"><th className="table-header-cell">Time</th><th className="table-header-cell">Detection</th><th className="table-header-cell">Path</th><th className="table-header-cell">Expert</th><th className="table-header-cell text-right">Confidence</th></tr></thead>
                <tbody>
                  {evidence.length ? evidence.map((alert) => (
                    <tr key={alert.id} className="row-hover cursor-pointer border-b last:border-0" onClick={() => navigate(`/alerts/${alert.id}`)}>
                      <td className="px-4 py-2 text-[10px] text-muted-foreground">{relativeTime(parseTimestamp(alert.timestamp))}</td>
                      <td className="px-4 py-2 text-[11px] font-medium">{alert.detection_type}</td>
                      <td className="mono px-4 py-2 text-[10px] text-muted-foreground">{alert.src_ip} → {alert.dst_ip || '—'}{alert.dst_port ? `:${alert.dst_port}` : ''}</td>
                      <td className="px-4 py-2 text-[11px] text-muted-foreground">{alert.primary_expert ?? '—'}</td>
                      <td className="px-4 py-2 text-right text-[11px] tabular-nums">{Math.round(alert.confidence * 100)}%</td>
                    </tr>
                  )) : <tr><td colSpan={5} className="px-4 py-10 text-center text-[12px] text-muted-foreground">No evidence records are available.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <div className="space-y-4">
          <section className="panel">
            <div className="panel-header"><div className="flex items-center gap-2"><Clock3 size={14} className="text-primary" /><h2 className="panel-title">Response sequence</h2></div></div>
            <div className="p-4">
              {playbook?.steps?.length ? (
                <ol className="space-y-4">
                  {playbook.steps.map((step, index) => (
                    <li key={step.step_id} className="relative flex gap-3">
                      <span className="z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary text-[10px] font-semibold text-primary-foreground">{index + 1}</span>
                      {index < playbook.steps.length - 1 && <span className="absolute left-3 top-6 h-[calc(100%+1rem)] w-px bg-border" />}
                      <div className="min-w-0 pb-1">
                        <div className="flex flex-wrap items-center gap-2"><p className="text-[12px] font-medium">{step.title}</p><Badge variant="outline" className="text-[9px] uppercase">{step.priority}</Badge>{step.auto_executable && <Badge variant="secondary" className="text-[9px]">Auto</Badge>}</div>
                        <p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{step.description}</p>
                        {step.target && <p className="mono mt-1 rounded bg-muted px-1.5 py-0.5 text-[10px]">Target {step.target}</p>}
                      </div>
                    </li>
                  ))}
                </ol>
              ) : (
                <ol className="space-y-3 text-[11px] text-muted-foreground">
                  {['Validate the affected entity and correlated evidence.', 'Contain confirmed malicious communication.', 'Eradicate persistence and close exposed access paths.', 'Monitor for recurrence before resolving.'].map((text, index) => (
                    <li key={text} className="flex gap-2.5"><span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-[9px] font-semibold text-foreground">{index + 1}</span><span className="pt-0.5">{text}</span></li>
                  ))}
                </ol>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header"><h2 className="panel-title">MITRE ATT&amp;CK</h2></div>
            <div className="p-4">
              {(playbook?.mitre_attack?.technique && playbook.mitre_attack.technique !== 'Unknown') ? (
                <>
                  <p className="mono text-[12px] font-medium">{playbook.mitre_attack.technique}</p>
                  <p className="mt-1 text-[11px] text-muted-foreground">{playbook.mitre_attack.tactic}</p>
                  <p className="mt-2 text-[11px] leading-5 text-muted-foreground">{playbook.mitre_attack.description}</p>
                </>
              ) : <p className="text-[11px] text-muted-foreground">No technique mapped for this incident.</p>}
            </div>
          </section>

          {frameworks && (
            <section className="panel">
              <div className="panel-header"><h2 className="panel-title">Framework mapping</h2><Badge variant="outline">{displayFamily(frameworks.family)}</Badge></div>
              <div className="space-y-3 p-4 text-[11px]">
                <div>
                  <div className="flex items-center justify-between gap-3"><span className="text-muted-foreground">NIST CSF 2.0</span><span className="font-medium">{frameworks.nist.function}</span></div>
                  <p className="mt-1 leading-5 text-muted-foreground">{frameworks.nist.practice}</p>
                </div>
                <div className="border-t pt-2">
                  <div className="flex items-center justify-between gap-3"><span className="text-muted-foreground">ISO 27001</span><span className="mono font-medium">{frameworks.iso.control}</span></div>
                  <p className="mt-1 leading-5 text-muted-foreground">{frameworks.iso.title}</p>
                </div>
                {frameworks.owasp && (
                  <div className="border-t pt-2">
                    <div className="flex items-center justify-between gap-3"><span className="text-muted-foreground">OWASP Top 10</span><span className="mono font-medium">{frameworks.owasp.id}</span></div>
                    <p className="mt-1 leading-5 text-muted-foreground">{frameworks.owasp.name}</p>
                  </div>
                )}
              </div>
            </section>
          )}

          <section className="panel">
            <div className="panel-header"><h2 className="panel-title">Classification</h2></div>
            <div className="space-y-2 p-4 text-[11px]">
              <Row label="Family" value={displayFamily(incident.family)} />
              <Row label="Entity" value={incident.entity} mono />
              <Row label="Signals" value={String(incident.count)} />
              <Row label="Peak confidence" value={`${Math.round(incident.peak_signal * 100)}%`} />
              <Row label="Status" value={incident.status} />
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="flex items-center justify-between gap-3 border-b pb-2 last:border-0 last:pb-0"><span className="text-muted-foreground">{label}</span><span className={cn('font-medium', mono && 'mono')}>{value}</span></div>;
}

function recommendedAction(family: string): 'isolate_host' | 'block_ip' | 'rate_limit' {
  const value = displayFamily(family).toLowerCase();
  if (value.includes('ddos') || value.includes('flood') || value.includes('denial')) return 'rate_limit';
  if (value.includes('brute') || value.includes('scan') || value.includes('recon')) return 'block_ip';
  return 'isolate_host';
}
