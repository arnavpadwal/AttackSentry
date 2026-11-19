import { useParams, useNavigate } from 'react-router-dom';
import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import { useAlert, useAlertPlaybook, useUpdateAlertStatus } from '@/queries/alerts';
import { parseTimestamp, relativeTime } from '@/lib/utils';
import { ArrowLeft } from 'lucide-react';

const ACTION_ICON: Record<string, string> = {
  block: 'Block', isolate: 'Isolate', investigate: 'Investigate',
  monitor: 'Monitor', escalate: 'Escalate', remediate: 'Remediate',
};

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: alert } = useAlert(id!);
  const { data: playbook } = useAlertPlaybook(id!);
  const update = useUpdateAlertStatus();

  if (!alert) {
    return <p className="p-8 text-center text-ink-faint">Alert not found</p>;
  }

  return (
    <div className="animate-fade-in space-y-6">
      <button onClick={() => navigate(-1)} className="flex items-center gap-1.5 text-sm text-ink-2 hover:text-ink">
        <ArrowLeft size={16} /> Back
      </button>

      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="page-title">{alert.detection_type}</h1>
            <Badge variant={alert.severity}>{alert.severity}</Badge>
          </div>
          <p className="page-subtitle">{alert.src_ip} → {alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ''} · {relativeTime(parseTimestamp(alert.timestamp))}</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" onClick={() => update.mutate({ id: alert.id, status: 'acknowledged' })}>Acknowledge</Button>
          <Button size="sm" variant="secondary" onClick={() => update.mutate({ id: alert.id, status: 'resolved' })}>Resolve</Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {playbook && (
            <Card title="AI Analyst Summary">
              <p className="text-sm leading-relaxed text-ink">{playbook.attack_summary}</p>
              {playbook.technical_analysis && (
                <p className="mt-3 text-sm leading-relaxed text-ink-2">{playbook.technical_analysis}</p>
              )}
            </Card>
          )}

          {playbook?.steps?.length ? (
            <Card title="Response Playbook">
              <ol className="space-y-3">
                {playbook.steps.map((step) => (
                  <li key={step.step_id} className="flex gap-3 rounded-lg border border-border p-3">
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-ink text-xs font-semibold text-ink-inverse">{step.step_id}</span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium text-ink">{step.title}</p>
                        <span className="rounded bg-surface-subtle px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-ink-faint">{ACTION_ICON[step.action_type] ?? step.action_type}</span>
                        <span className="text-[10px] uppercase tracking-wide text-ink-faint">{step.priority}</span>
                      </div>
                      <p className="mt-1 text-sm text-ink-2">{step.description}</p>
                      {step.target && <p className="mt-1 text-xs text-ink-faint">Target: {step.target}</p>}
                    </div>
                  </li>
                ))}
              </ol>
            </Card>
          ) : (
            <Card title="Response Playbook"><p className="text-sm text-ink-faint">No playbook available.</p></Card>
          )}
        </div>

        <div className="space-y-4">
          <Card title="Classification">
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between"><dt className="text-ink-faint">Severity</dt><dd className="font-medium text-ink">{alert.severity}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Confidence</dt><dd className="text-ink">{Math.round(alert.confidence * 100)}%</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Anomaly score</dt><dd className="text-ink">{alert.anomaly_score.toFixed(3)}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Classification</dt><dd className="text-ink">{alert.mitre_technique ?? 'Behavioral anomaly'}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Entity risk</dt><dd className="text-ink">{alert.entity_risk.toFixed(0)}</dd></div>
            </dl>
          </Card>

          {((alert.mitre_technique && alert.mitre_technique !== 'Unknown') || (playbook?.mitre_attack?.technique && playbook.mitre_attack.technique !== 'Unknown')) && (
            <Card title="MITRE ATT&CK">
              <div className="flex items-center gap-2">
                <span className="rounded bg-surface-subtle px-2 py-0.5 text-xs font-mono text-ink">{alert.mitre_technique || playbook?.mitre_attack?.technique}</span>
                <span className="text-sm text-ink">{alert.mitre_tactic || playbook?.mitre_attack?.tactic}</span>
              </div>
              <p className="mt-2 text-xs text-ink-faint">{alert.mitre_description || playbook?.mitre_attack?.description}</p>
            </Card>
          )}

          <Card title="Context">
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between"><dt className="text-ink-faint">Group</dt><dd className="text-ink">{alert.group_name ?? '—'}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Identity</dt><dd className="text-ink">{alert.identity ?? '—'}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Process</dt><dd className="text-ink">{alert.process_name ?? '—'}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-faint">Subnet</dt><dd className="text-ink">{alert.subnet ?? '—'}</dd></div>
            </dl>
          </Card>
        </div>
      </div>
    </div>
  );
}
