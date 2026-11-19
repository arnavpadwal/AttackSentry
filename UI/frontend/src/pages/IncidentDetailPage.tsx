import type { ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, CheckCircle2, ShieldOff, Sparkles } from 'lucide-react';
import Card from '@/components/shared/Card';
import EmptyState from '@/components/shared/EmptyState';
import PageHeader from '@/components/shared/PageHeader';
import SeverityBadge, { severityDot } from '@/components/shared/SeverityBadge';
import Button from '@/components/shared/Button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { useGenerateIncidentPlaybook, useIncident, useIncidentAlerts, useIncidentPlaybook, useRequestMitigation, useUpdateIncidentStatus } from '@/queries/incidents';
import { cn, displayFamily, parseTimestamp, relativeTime } from '@/lib/utils';
import { useAuthStore } from '@/stores';

const railBorder: Record<string, string> = {
  critical: 'border-severity-critical',
  high: 'border-severity-high',
  medium: 'border-severity-medium',
  low: 'border-severity-low',
  info: 'border-severity-info',
};

function stamp(value: string | null | undefined) {
  const ts = parseTimestamp(value);
  return ts ? new Date(ts).toLocaleString() : '—';
}

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

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-80" />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-4"><Skeleton className="h-40" /><Skeleton className="h-64" /></div>
          <div className="space-y-4"><Skeleton className="h-44" /><Skeleton className="h-28" /></div>
        </div>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="panel">
        <EmptyState
          icon={ShieldOff}
          title="Incident not found"
          description="This incident may have been merged into another case or removed by retention."
          action={<Button size="sm" variant="outline" onClick={() => navigate('/threats')}>Return to queue</Button>}
        />
      </div>
    );
  }

  const active = incident.status !== 'resolved';
  const sourceEntities = [...new Set((alerts ?? []).map((alert) => alert.src_ip).filter(Boolean))] as string[];
  const recommended = recommendedAction(incident.family);
  const evidence = (alerts ?? []).slice(0, 50);
  const frameworks = evidence[0]?.frameworks;
  const pendingAction = requestMitigation.isPending ? requestMitigation.variables?.action : undefined;
  const family = displayFamily(incident.family);

  return (
    <div className="space-y-4">
      <button onClick={() => navigate(-1)} className="inline-flex items-center gap-1 text-[11.5px] text-muted-foreground hover:text-foreground">
        <ArrowLeft size={13} strokeWidth={1.5} /> Back to incident queue
      </button>

      <PageHeader
        className={cn('border-l-2 pl-3', railBorder[incident.severity] ?? railBorder.info)}
        title={family}
        description={`Affected entity ${incident.entity} · ${incident.count} correlated signals · last activity ${relativeTime(parseTimestamp(incident.last_seen))}`}
        meta={
          <>
            <SeverityBadge severity={incident.severity} />
            <Badge variant="muted" className="capitalize">{incident.status}</Badge>
            <span className="mono text-[11px] text-muted-foreground">{incident.id}</span>
          </>
        }
        actions={
          <>
            {(!playbook || playbook.is_fallback) && (
              <Button
                size="sm"
                variant="outline"
                disabled={generatePlaybook.isPending}
                onClick={() => generatePlaybook.mutate(id)}
              >
                <Sparkles size={13} strokeWidth={1.5} /> {generatePlaybook.isPending ? 'Generating…' : 'Generate assessment'}
              </Button>
            )}
            {active && incident.status === 'open' && (
              <Button
                size="sm"
                variant="outline"
                loading={update.isPending && update.variables?.status === 'acknowledged'}
                disabled={update.isPending}
                onClick={() => update.mutate({ id, status: 'acknowledged' })}
              >
                Acknowledge
              </Button>
            )}
            {active ? (
              <Button
                size="sm"
                loading={update.isPending && update.variables?.status === 'resolved'}
                disabled={update.isPending}
                onClick={() => update.mutate({ id, status: 'resolved' })}
              >
                <CheckCircle2 size={13} strokeWidth={1.5} /> Resolve
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                loading={update.isPending && update.variables?.status === 'open'}
                disabled={update.isPending}
                onClick={() => update.mutate({ id, status: 'open' })}
              >
                Reopen
              </Button>
            )}
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          <Card title="What happened">
            {playbook ? (
              <div className="space-y-2">
                <p className="text-[13px] leading-6">{playbook.attack_summary}</p>
                {playbook.technical_analysis && (
                  <p className="text-[12px] leading-6 text-muted-foreground">{playbook.technical_analysis}</p>
                )}
                {playbook.false_positive_assessment && (
                  <p className="text-[11.5px] leading-5 text-muted-foreground">False-positive assessment: {playbook.false_positive_assessment}</p>
                )}
                {playbook.is_fallback && (
                  <p className="text-[11px] text-muted-foreground">Provider offline — this guidance is deterministic.</p>
                )}
                <p className="text-[11px] text-muted-foreground">Assessment severity {playbook.severity} · confidence {playbook.confidence}</p>
              </div>
            ) : (
              <p className="text-[13px] leading-6">
                {family} activity was correlated across {incident.count} signals from {incident.entity}.
              </p>
            )}
          </Card>

          <Card
            title="Correlated detections"
            subtitle={`${evidence.length} of ${alerts?.length ?? 0} records`}
            noPadding
          >
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Detection</th>
                    <th>Family</th>
                    <th>Path</th>
                    <th><div className="text-right">Score</div></th>
                    <th><div className="text-right">Time</div></th>
                  </tr>
                </thead>
                <tbody>
                  {evidence.length ? evidence.map((alert) => (
                    <tr key={alert.id} className="cursor-pointer" onClick={() => navigate(`/alerts/${alert.id}`)}>
                      <td>
                        <span className="flex items-center gap-2">
                          <span className={cn('h-3.5 w-[3px] shrink-0 rounded-full', severityDot[alert.severity] ?? severityDot.info)} aria-hidden />
                          <span className="text-[12px] font-medium">{alert.detection_type}</span>
                        </span>
                      </td>
                      <td><span className="text-[11.5px] text-muted-foreground">{displayFamily(alert.frameworks?.family ?? alert.primary_expert)}</span></td>
                      <td><span className="mono text-[11.5px] text-muted-foreground">{alert.src_ip} → {alert.dst_ip || '—'}{alert.dst_port ? `:${alert.dst_port}` : ''}</span></td>
                      <td><div className="text-right"><span className="text-[11.5px] tabular-nums">{Math.round(alert.confidence * 100)}%</span></div></td>
                      <td><div className="text-right"><span className="mono text-[11.5px] text-muted-foreground" title={stamp(alert.timestamp)}>{relativeTime(parseTimestamp(alert.timestamp))}</span></div></td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan={5}>
                        <EmptyState
                          title="No detections attached"
                          description="Signals are still being correlated for this incident, or retention has cleared them."
                        />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title="Timeline">
            <dl className="space-y-3 text-[12px]">
              <TimeRow label="First observed" value={incident.created_at} />
              <TimeRow label="Last activity" value={incident.last_seen} />
              {incident.resolved_at && <TimeRow label="Resolved" value={incident.resolved_at} />}
            </dl>
          </Card>

          <Card
            title="Response playbook"
            action={playbook?.is_fallback ? <span className="text-[11px] text-muted-foreground">Deterministic guidance</span> : undefined}
          >
            {generatePlaybook.isPending ? (
              <div className="space-y-4">
                <p className="text-[11px] text-muted-foreground">Generating assessment…</p>
                {[0, 1, 2].map((row) => (
                  <div key={row} className="flex gap-3">
                    <Skeleton className="h-5 w-5 shrink-0 rounded-full" />
                    <div className="flex-1 space-y-1.5"><Skeleton className="h-3 w-1/3" /><Skeleton className="h-3 w-3/4" /></div>
                  </div>
                ))}
              </div>
            ) : playbook?.steps?.length ? (
              <ol className="space-y-4">
                {playbook.steps.map((step, index) => (
                  <li key={step.step_id} className="flex gap-3">
                    <span className="mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10.5px] text-muted-foreground">{index + 1}</span>
                    <div className="min-w-0">
                      <p className="text-[12.5px] font-medium leading-5 text-foreground">{step.title}</p>
                      <p className="mt-0.5 text-[11.5px] leading-5 text-muted-foreground">{step.description}</p>
                      <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                        <span className="capitalize">{step.priority} priority</span>
                        <span>{step.auto_executable ? 'Auto-executable' : 'Manual'}</span>
                        {step.target && <span className="mono text-foreground/80">target {step.target}</span>}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <EmptyState
                icon={Sparkles}
                title="No assessment yet"
                description="The first assessment runs automatically after an incident is created. Generate one now to retry."
                action={
                  <Button size="sm" disabled={generatePlaybook.isPending} onClick={() => generatePlaybook.mutate(id)}>
                    <Sparkles size={13} strokeWidth={1.5} /> Generate assessment
                  </Button>
                }
              />
            )}
            {playbook?.sources?.length ? (
              <div className="mt-4 border-t pt-3">
                <p className="label mb-1.5">References</p>
                <ul className="space-y-1">
                  {playbook.sources.map((source) => (
                    <li key={source.id} className="text-[11px] leading-5 text-muted-foreground">
                      <span className="text-foreground/80">{source.source}</span>
                      <span className="mx-1">·</span>
                      {source.url ? (
                        <a href={source.url} target="_blank" rel="noreferrer" className="hover:text-foreground hover:underline">{source.title}</a>
                      ) : (
                        source.title
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="Classification">
            <dl className="space-y-2.5 text-[12px]">
              <Row label="Severity" value={<SeverityBadge severity={incident.severity} />} />
              <Row label="Status" value={<span className="capitalize">{incident.status}</span>} />
              <Row label="Family" value={family} />
              <Row label="Signals" value={String(incident.count)} mono />
              <Row label="Peak confidence" value={`${Math.round(incident.peak_signal * 100)}%`} mono />
            </dl>
          </Card>

          <Card title="Response">
            <p className="text-[11.5px] leading-5 text-muted-foreground">
              {active
                ? 'Manual containment requests apply to the affected entity until their TTL expires and are recorded in the response log.'
                : 'Incident resolved. Containment requests are closed.'}
            </p>
            {active && role !== 'viewer' && (
              <div className="mt-3 space-y-1.5">
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full justify-start capitalize"
                  disabled={requestMitigation.isPending}
                  loading={pendingAction === recommended}
                  onClick={() => requestMitigation.mutate({ incident_id: id, action: recommended, reason: `Attack-aware ${recommended.replace(/_/g, ' ')} requested from incident ${id}`, ttl_minutes: 60 })}
                >
                  Apply {recommended.replace(/_/g, ' ')}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full justify-start"
                  disabled={requestMitigation.isPending}
                  loading={pendingAction === 'isolate_host'}
                  onClick={() => requestMitigation.mutate({ incident_id: id, action: 'isolate_host', reason: `Host isolation requested from incident ${id}`, ttl_minutes: 60 })}
                >
                  <ShieldOff size={13} strokeWidth={1.5} /> Isolate host
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full justify-start"
                  disabled={requestMitigation.isPending}
                  loading={pendingAction === 'block_ip'}
                  onClick={() => requestMitigation.mutate({ incident_id: id, action: 'block_ip', reason: `Source block requested from incident ${id}`, ttl_minutes: 60 })}
                >
                  Block source IP
                </Button>
              </div>
            )}
            {active && role === 'viewer' && (
              <p className="mt-3 text-[11.5px] text-muted-foreground">View-only role. Containment needs analyst access.</p>
            )}
          </Card>

          <Card title="Entities">
            <dl className="space-y-2.5 text-[12px]">
              <Row
                label="Affected host"
                value={<Link to={`/hosts?search=${encodeURIComponent(incident.entity)}`} className="mono hover:text-primary">{incident.entity}</Link>}
              />
              <Row label="Sources" value={sourceEntities.length ? String(sourceEntities.length) : '—'} mono />
            </dl>
            {sourceEntities.length > 1 && (
              <div className="mt-3 flex flex-wrap gap-1.5 border-t pt-3">
                {sourceEntities.slice(0, 40).map((ip) => (
                  <span key={ip} className="mono rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground">{ip}</span>
                ))}
              </div>
            )}
          </Card>

          <Card title="MITRE ATT&CK">
            {playbook?.mitre_attack?.technique && playbook.mitre_attack.technique !== 'Unknown' ? (
              <div className="space-y-1">
                <p className="mono text-[12px] font-medium text-foreground">{playbook.mitre_attack.technique}</p>
                <p className="text-[11.5px] text-muted-foreground">{playbook.mitre_attack.tactic}</p>
                <p className="pt-1 text-[11.5px] leading-5 text-muted-foreground">{playbook.mitre_attack.description}</p>
              </div>
            ) : (() => {
              const mapped = (alerts ?? []).find((alert) => alert.mitre_technique && alert.mitre_technique !== 'Unknown');
              if (!mapped) {
                return <p className="text-[11.5px] text-muted-foreground">No technique mapped for this incident.</p>;
              }
              return (
                <div className="space-y-1">
                  <p className="mono text-[12px] font-medium text-foreground">{mapped.mitre_technique}</p>
                  <p className="text-[11.5px] text-muted-foreground">{mapped.mitre_tactic ?? 'Unknown tactic'}</p>
                  {mapped.mitre_description && (
                    <p className="pt-1 text-[11.5px] leading-5 text-muted-foreground">{mapped.mitre_description}</p>
                  )}
                  <p className="pt-1 text-[10.5px] text-muted-foreground">From the correlated detection evidence.</p>
                </div>
              );
            })()}
          </Card>

          {frameworks && (
            <Card title="Framework mapping" action={<Badge variant="outline">{displayFamily(frameworks.family)}</Badge>}>
              <dl className="space-y-3 text-[11.5px]">
                <div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-muted-foreground">NIST CSF 2.0</dt>
                    <dd className="font-medium">{frameworks.nist.function}</dd>
                  </div>
                  <p className="mt-1 leading-5 text-muted-foreground">{frameworks.nist.practice}</p>
                </div>
                <div className="border-t pt-3">
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-muted-foreground">ISO 27001</dt>
                    <dd className="mono font-medium">{frameworks.iso.control}</dd>
                  </div>
                  <p className="mt-1 leading-5 text-muted-foreground">{frameworks.iso.title}</p>
                </div>
                {frameworks.owasp && (
                  <div className="border-t pt-3">
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-muted-foreground">OWASP Top 10</dt>
                      <dd className="mono font-medium">{frameworks.owasp.id}</dd>
                    </div>
                    <p className="mt-1 leading-5 text-muted-foreground">{frameworks.owasp.name}</p>
                  </div>
                )}
              </dl>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className={cn('min-w-0 break-words text-right font-medium text-foreground', mono && 'mono font-normal text-[11.5px]')}>{value}</dd>
    </div>
  );
}

function TimeRow({ label, value }: { label: string; value: string }) {
  const ts = parseTimestamp(value);
  return (
    <div className="flex items-start justify-between gap-3">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-right">
        <span className="mono block text-[11.5px] text-foreground">{ts ? new Date(ts).toLocaleString() : '—'}</span>
        {ts > 0 && <span className="block text-[11px] text-muted-foreground">{relativeTime(ts)}</span>}
      </dd>
    </div>
  );
}

function recommendedAction(family: string): 'isolate_host' | 'block_ip' | 'rate_limit' {
  const value = displayFamily(family).toLowerCase();
  if (value.includes('ddos') || value.includes('flood') || value.includes('denial')) return 'rate_limit';
  if (value.includes('brute') || value.includes('scan') || value.includes('recon')) return 'block_ip';
  return 'isolate_host';
}
