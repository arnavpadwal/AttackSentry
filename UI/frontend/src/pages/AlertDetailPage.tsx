import type { ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Crosshair, ShieldOff, Sparkles } from 'lucide-react';
import Card from '@/components/shared/Card';
import EmptyState from '@/components/shared/EmptyState';
import PageHeader from '@/components/shared/PageHeader';
import SeverityBadge from '@/components/shared/SeverityBadge';
import Button from '@/components/shared/Button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useAlert, useAlertPlaybook, useUpdateAlertStatus } from '@/queries/alerts';
import { useRequestMitigation } from '@/queries/incidents';
import { useAuthStore } from '@/stores';
import { cn, displayFamily, parseTimestamp, relativeTime } from '@/lib/utils';

const railBorder: Record<string, string> = {
  critical: 'border-severity-critical',
  high: 'border-severity-high',
  medium: 'border-severity-medium',
  low: 'border-severity-low',
  info: 'border-severity-info',
};

const PROTOCOL: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };

const ACTION_LABEL: Record<string, string> = {
  block: 'Block', isolate: 'Isolate', investigate: 'Investigate',
  monitor: 'Monitor', escalate: 'Escalate', remediate: 'Remediate',
};

function stamp(value: string | null | undefined) {
  const ts = parseTimestamp(value);
  return ts ? new Date(ts).toLocaleString() : '—';
}

function known(value: string | null | undefined) {
  return value && value !== 'Unknown' ? value : null;
}

export default function AlertDetailPage() {
  const { id = '' } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: alert, isLoading } = useAlert(id);
  const { data: playbook, isLoading: playbookLoading } = useAlertPlaybook(id);
  const update = useUpdateAlertStatus();
  const contain = useRequestMitigation();
  const role = useAuthStore((state) => state.user?.role);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-80" />
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-4"><Skeleton className="h-36" /><Skeleton className="h-64" /></div>
          <div className="space-y-4"><Skeleton className="h-48" /><Skeleton className="h-28" /></div>
        </div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="panel">
        <EmptyState
          icon={Crosshair}
          title="Detection not found"
          description="This detection may have been correlated into an incident or removed by retention."
          action={<Button size="sm" variant="outline" onClick={() => navigate('/threats')}>Back to detections</Button>}
        />
      </div>
    );
  }

  const incidentId = alert.incident_id;
  const technique = known(alert.mitre_technique) ?? known(playbook?.mitre_attack?.technique);
  const tactic = known(alert.mitre_tactic) ?? known(playbook?.mitre_attack?.tactic);
  const techniqueNote = known(alert.mitre_description) ?? known(playbook?.mitre_attack?.description);
  const destination = `${alert.dst_ip ?? 'unknown destination'}${alert.dst_port ? `:${alert.dst_port}` : ''}`;

  return (
    <div className="space-y-4">
      <button onClick={() => navigate(-1)} className="inline-flex items-center gap-1 text-[11.5px] text-muted-foreground hover:text-foreground">
        <ArrowLeft size={13} strokeWidth={1.5} /> Back
      </button>

      <PageHeader
        className={cn('border-l-2 pl-3', railBorder[alert.severity] ?? railBorder.info)}
        title={alert.detection_type}
        description={`${alert.src_ip ?? 'unknown source'} → ${destination} · ${stamp(alert.timestamp)} · ${relativeTime(parseTimestamp(alert.timestamp))}`}
        meta={
          <>
            <SeverityBadge severity={alert.severity} />
            <Badge variant="muted" className="capitalize">{alert.status}</Badge>
            {incidentId && (
              <Link to={`/incidents/${incidentId}`} className="mono text-[11px] text-muted-foreground hover:text-foreground">
                Incident {incidentId}
              </Link>
            )}
          </>
        }
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              loading={update.isPending && update.variables?.status === 'acknowledged'}
              disabled={update.isPending}
              onClick={() => update.mutate({ id: alert.id, status: 'acknowledged' })}
            >
              Acknowledge
            </Button>
            <Button
              size="sm"
              loading={update.isPending && update.variables?.status === 'resolved'}
              disabled={update.isPending}
              onClick={() => update.mutate({ id: alert.id, status: 'resolved' })}
            >
              Resolve
            </Button>
            {role !== 'viewer' && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!incidentId || contain.isPending}
                    title={incidentId ? undefined : 'This detection is not linked to an incident, so containment cannot be requested.'}
                  >
                    <ShieldOff size={13} strokeWidth={1.5} /> {contain.isPending ? 'Requesting…' : 'Contain'}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuItem
                    onClick={() => {
                      if (!incidentId) return;
                      contain.mutate({ incident_id: incidentId, action: 'isolate_host', reason: `Host isolation requested from alert ${alert.id}`, ttl_minutes: 60 });
                    }}
                  >
                    Isolate host
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    disabled={!alert.src_ip}
                    onClick={() => {
                      if (!incidentId || !alert.src_ip) return;
                      contain.mutate({ incident_id: incidentId, action: 'block_ip', reason: `Source block requested from alert ${alert.id}`, ttl_minutes: 60 });
                    }}
                  >
                    Block source IP
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          <Card title="What happened">
            {playbookLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-3.5 w-full" />
                <Skeleton className="h-3.5 w-11/12" />
                <Skeleton className="h-3.5 w-2/3" />
                <p className="pt-1 text-[11px] text-muted-foreground">Generating assessment…</p>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-[13px] leading-6">
                  {playbook?.attack_summary ?? `${alert.detection_type} was flagged between ${alert.src_ip ?? 'an unknown source'} and ${destination}.`}
                </p>
                {playbook?.technical_analysis && (
                  <p className="text-[12px] leading-6 text-muted-foreground">{playbook.technical_analysis}</p>
                )}
                {alert.reason && (
                  <p className="text-[11.5px] leading-5 text-muted-foreground">Reason: {alert.reason}</p>
                )}
                {playbook?.false_positive_assessment && (
                  <p className="text-[11.5px] leading-5 text-muted-foreground">False-positive assessment: {playbook.false_positive_assessment}</p>
                )}
                {playbook?.is_fallback && (
                  <p className="text-[11px] text-muted-foreground">Provider offline — this guidance is deterministic.</p>
                )}
              </div>
            )}
          </Card>

          <Card title="Evidence">
            <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
              <Field label="Source" value={alert.src_ip ?? '—'} mono />
              <Field label="Destination" value={destination} mono />
              <Field label="Protocol" value={alert.protocol ? PROTOCOL[alert.protocol] ?? `IP ${alert.protocol}` : '—'} />
              <Field label="Anomaly score" value={alert.anomaly_score.toFixed(3)} mono />
              <Field label="Confidence" value={`${Math.round(alert.confidence * 100)}%`} mono />
              <Field label="Entity" value={alert.group_name ?? alert.identity ?? alert.src_ip ?? '—'} />
              <Field label="Device type" value={alert.device_type ?? '—'} />
              <Field label="Subnet" value={alert.subnet ?? '—'} mono />
            </dl>
          </Card>

          <Card
            title="Response playbook"
            action={playbook?.is_fallback ? <span className="text-[11px] text-muted-foreground">Deterministic guidance</span> : undefined}
          >
            {playbookLoading ? (
              <div className="space-y-4">
                <p className="text-[11px] text-muted-foreground">Generating playbook…</p>
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
                        <span>{ACTION_LABEL[step.action_type] ?? step.action_type}</span>
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
                title="No playbook for this detection"
                description="Playbooks are written per incident. Open the linked incident to read its response plan."
                action={incidentId ? <Button size="sm" variant="outline" onClick={() => navigate(`/incidents/${incidentId}`)}>Open incident</Button> : undefined}
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
              <Row label="Severity" value={<SeverityBadge severity={alert.severity} />} />
              <Row label="Confidence" value={`${Math.round(alert.confidence * 100)}%`} mono />
              <Row label="Family" value={displayFamily(alert.frameworks?.family)} />
              <Row label="Status" value={<span className="capitalize">{alert.status}</span>} />
            </dl>
          </Card>

          <Card title="MITRE ATT&CK">
            {technique ? (
              <div className="space-y-1">
                <p className="mono text-[12px] font-medium text-foreground">{technique}</p>
                {tactic && <p className="text-[11.5px] text-muted-foreground">{tactic}</p>}
                {techniqueNote && <p className="pt-1 text-[11.5px] leading-5 text-muted-foreground">{techniqueNote}</p>}
              </div>
            ) : (
              <p className="text-[11.5px] text-muted-foreground">No technique mapped for this detection.</p>
            )}
          </Card>

          <Card title="Entity">
            <dl className="space-y-2.5 text-[12px]">
              <Row
                label="Host"
                value={alert.src_ip
                  ? <Link to={`/hosts?search=${encodeURIComponent(alert.src_ip)}`} className="mono hover:text-primary">{alert.src_ip}</Link>
                  : '—'}
                mono={!alert.src_ip}
              />
              <Row label="Destination" value={destination} mono />
              <Row label="Entity risk" value={alert.entity_risk.toFixed(0)} mono />
              <Row label="Group" value={alert.group_name ?? '—'} />
              <Row label="Identity" value={alert.identity ?? '—'} />
              <Row label="Process" value={alert.process_name ?? '—'} mono={Boolean(alert.process_name)} />
            </dl>
          </Card>

          <Card title="Timeline">
            <dl className="space-y-2.5 text-[12px]">
              <Row label="Detected" value={stamp(alert.timestamp)} mono />
              <Row label="Seen" value={relativeTime(parseTimestamp(alert.timestamp))} />
              {playbook && <Row label="Assessment" value={stamp(playbook.created_at)} mono />}
            </dl>
          </Card>
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

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="label">{label}</dt>
      <dd className={cn('mt-0.5 truncate text-[12px] text-foreground', mono && 'mono')}>{value}</dd>
    </div>
  );
}
