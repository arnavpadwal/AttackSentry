import { useEffect, useState } from 'react';
import { Ban, CheckCircle2, Plus, ShieldCheck, XCircle } from 'lucide-react';
import type { Mitigation } from '@/types';
import PageHeader from '@/components/shared/PageHeader';
import Metric from '@/components/shared/Metric';
import EmptyState from '@/components/shared/EmptyState';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import Card from '@/components/shared/Card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useIncidents, useMitigationDecision, useMitigations, useRequestMitigation } from '@/queries/incidents';
import { useSettings, useTestWebhook, useUpdateSettings } from '@/queries/settings';
import { useAuthStore } from '@/stores';
import { parseTimestamp, relativeTime } from '@/lib/utils';

type ResponseForm = {
  webhook_url: string; webhook_secret: string; webhook_min_severity: 'low' | 'medium' | 'high' | 'critical';
  response_mode: 'disabled' | 'approval' | 'automatic'; response_min_severity: 'low' | 'medium' | 'high' | 'critical';
  response_min_confidence: number; response_action: 'dynamic' | 'isolate_host' | 'block_ip' | 'rate_limit'; response_ttl_minutes: number; response_auto_resolve: boolean;
};

const ACTIVE_STATUSES = ['dispatched', 'release_failed'];
const HOUR_MS = 3_600_000;

const ACTION_LABEL: Record<string, string> = {
  isolate_host: 'Isolate host',
  block_ip: 'Block IP',
  rate_limit: 'Rate limit',
};

function statusVariant(status: string) {
  if (status === 'failed') return 'critical' as const;
  if (status === 'dispatched') return 'low' as const;
  if (status === 'pending_approval') return 'medium' as const;
  if (status === 'cancelled') return 'default' as const;
  return 'info' as const;
}

function expiryLabel(expiresAt: string | null): string {
  const ts = parseTimestamp(expiresAt);
  if (!expiresAt || !ts) return 'No expiry';
  const diff = ts - Date.now();
  if (diff <= 0) return 'Expired';
  if (diff < HOUR_MS) return `${Math.max(1, Math.round(diff / 60_000))} min left`;
  return `${Math.round(diff / HOUR_MS)} h left`;
}

export default function ResponsePage() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';
  const { data: settings } = useSettings();
  const { data: actions, isLoading } = useMitigations();
  const { data: incidents } = useIncidents();
  const update = useUpdateSettings();
  const testWebhook = useTestWebhook();
  const decision = useMitigationDecision();
  const request = useRequestMitigation();
  const [message, setMessage] = useState('');
  const [formError, setFormError] = useState('');
  const [containOpen, setContainOpen] = useState(false);
  const [releaseTarget, setReleaseTarget] = useState<Mitigation | null>(null);
  const [target, setTarget] = useState('');
  const [action, setAction] = useState<'isolate_host' | 'block_ip' | 'rate_limit'>('isolate_host');
  const [reason, setReason] = useState('');
  const [ttl, setTtl] = useState(60);
  const [form, setForm] = useState<ResponseForm>({
    webhook_url: '', webhook_secret: '', webhook_min_severity: 'high', response_mode: 'disabled',
    response_min_severity: 'critical', response_min_confidence: 0.9,
    response_action: 'dynamic', response_ttl_minutes: 60, response_auto_resolve: false,
  });

  useEffect(() => {
    if (settings) setForm((current) => ({
      ...current, webhook_url: settings.webhook_url, webhook_min_severity: settings.webhook_min_severity,
      response_mode: settings.response_mode, response_min_severity: settings.response_min_severity,
      response_min_confidence: settings.response_min_confidence, response_action: settings.response_action,
      response_ttl_minutes: settings.response_ttl_minutes, response_auto_resolve: settings.response_auto_resolve,
    }));
  }, [settings]);

  const items = actions ?? [];
  const active = items.filter((item) => ACTIVE_STATUSES.includes(item.status));
  const isolated = active.filter((item) => item.action === 'isolate_host').length;
  const expiring = active.filter((item) => {
    const ts = parseTimestamp(item.expires_at);
    return Boolean(item.expires_at) && ts > Date.now() && ts - Date.now() <= HOUR_MS;
  }).length;
  const last24h = items.filter((item) => Date.now() - parseTimestamp(item.created_at) <= 86_400_000).length;
  const pending = items.filter((item) => ['pending_approval', 'queued', 'failed'].includes(item.status)).length;

  const openContain = () => {
    setFormError('');
    setTtl(settings?.response_ttl_minutes ?? 60);
    setContainOpen(true);
  };

  const submitContain = async () => {
    setFormError('');
    if (!target) { setFormError('Choose the incident to contain.'); return; }
    if (reason.trim().length < 3) { setFormError('Add a reason of at least 3 characters.'); return; }
    try {
      await request.mutateAsync({ incident_id: target, action, reason: reason.trim(), ttl_minutes: ttl });
      setContainOpen(false);
      setTarget('');
      setReason('');
    } catch {
      setFormError('The containment request failed. Check the incident and try again.');
    }
  };

  const release = (item: Mitigation) => {
    setReleaseTarget(item);
  };

  const confirmRelease = async () => {
    if (!releaseTarget) return;
    try {
      await decision.mutateAsync({ id: releaseTarget.id, decision: 'release' });
      setReleaseTarget(null);
    } catch {
      setReleaseTarget(null);
      setMessage('Release failed. The control may already have been released.');
    }
  };

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader
        title="Response"
        description="Active containments, their expiry, and the policy that decides when AttackSentry acts on its own."
        meta={
          <span className="meta">
            {active.length} active · {pending} awaiting approval · policy {settings?.response_mode ?? 'disabled'}
          </span>
        }
        actions={
          <Button size="sm" onClick={openContain} disabled={!incidents?.length} title={incidents?.length ? undefined : 'No incidents available to contain'}>
            <Plus size={14} strokeWidth={1.5} /> Contain
          </Button>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Active blocks" value={active.length} hint="Dispatched controls not yet released" />
        <Metric label="Hosts isolated" value={isolated} hint="Active isolate-host controls" />
        <Metric label="Expiring within 1h" value={expiring} tone={expiring ? 'medium' : 'default'} hint="Auto-release on TTL" />
        <Metric label="Actions 24h" value={last24h} hint="Requests, approvals and releases" />
      </div>

      <Card
        title="Active containments"
        subtitle="Controls currently enforced at the target"
        noPadding
        action={<span className="meta">{active.length} of {items.length} controls</span>}
      >
        <div className="overflow-x-auto">
          <table className="table-shell min-w-[860px]">
            <thead>
              <tr>
                <th>Target</th>
                <th>Action</th>
                <th>Reason</th>
                <th>Created</th>
                <th>Expires</th>
                <th className="text-right">Release</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={6}><Skeleton className="h-4 w-full" /></td></tr>
              ) : active.length ? (
                active.map((item) => (
                  <tr key={item.id}>
                    <td className="mono text-[12px]" title={item.incident_id}>{item.entity}</td>
                    <td>
                      <span className="block">{ACTION_LABEL[item.action] ?? item.action.replace(/_/g, ' ')}</span>
                      {item.provider_message && (
                        <span className="block max-w-[260px] truncate text-[10.5px] text-muted-foreground" title={item.provider_message}>
                          {item.provider_message}
                        </span>
                      )}
                    </td>
                    <td className="max-w-[320px] truncate text-muted-foreground">{item.reason}</td>
                    <td>
                      <span className="meta" title={new Date(parseTimestamp(item.created_at)).toLocaleString()}>
                        {relativeTime(parseTimestamp(item.created_at))}
                      </span>
                    </td>
                    <td>
                      <span className="meta">{expiryLabel(item.expires_at)}</span>
                    </td>
                    <td className="text-right">
                      <Button size="sm" variant="outline" disabled={!isAdmin} onClick={() => release(item)}>
                        Release
                      </Button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={ShieldCheck}
                      title="No active containments"
                      description="Accepted blocks and isolations appear here with their target, reason and expiry. Request containment to start one."
                      action={<Button size="sm" variant="outline" onClick={openContain} disabled={!incidents?.length}><Plus size={14} strokeWidth={1.5} /> Contain</Button>}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {isAdmin && (
        <div className="grid gap-3 xl:grid-cols-2">
          <Card title="Response policy" subtitle="Automatic mode dispatches only incidents above both thresholds">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="space-y-1.5">
                <span className="label">Mode</span>
                <Select value={form.response_mode} onValueChange={(value) => setForm({ ...form, response_mode: value as ResponseForm['response_mode'] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="disabled">Disabled</SelectItem>
                    <SelectItem value="approval">Require approval</SelectItem>
                    <SelectItem value="automatic">Automatic</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label className="space-y-1.5">
                <span className="label">Action strategy</span>
                <Select value={form.response_action} onValueChange={(value) => setForm({ ...form, response_action: value as ResponseForm['response_action'] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="dynamic">Dynamic by attack type</SelectItem>
                    <SelectItem value="isolate_host">Always isolate host</SelectItem>
                    <SelectItem value="block_ip">Always block IP</SelectItem>
                    <SelectItem value="rate_limit">Always rate limit</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label className="space-y-1.5">
                <span className="label">Minimum severity</span>
                <Select value={form.response_min_severity} onValueChange={(value) => setForm({ ...form, response_min_severity: value as ResponseForm['response_min_severity'] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label className="space-y-1.5">
                <span className="label">Minimum confidence</span>
                <Input type="number" min="0" max="1" step="0.05" value={form.response_min_confidence} onChange={(event) => setForm({ ...form, response_min_confidence: Number(event.target.value) })} />
              </label>
              <label className="space-y-1.5">
                <span className="label">Control lifetime (minutes)</span>
                <Input type="number" min="5" max="10080" value={form.response_ttl_minutes} onChange={(event) => setForm({ ...form, response_ttl_minutes: Number(event.target.value) })} />
              </label>
              <div className="flex items-center justify-between gap-3 self-end rounded-md border px-3 py-2">
                <span className="text-[12px] text-foreground">Auto-resolve after mitigation</span>
                <Switch aria-label="Auto-resolve after successful mitigation" checked={form.response_auto_resolve} onCheckedChange={(checked) => setForm({ ...form, response_auto_resolve: checked })} />
              </div>
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <Button size="sm" onClick={() => update.mutate({ response_mode: form.response_mode, response_action: form.response_action, response_min_severity: form.response_min_severity, response_min_confidence: form.response_min_confidence, response_ttl_minutes: form.response_ttl_minutes, response_auto_resolve: form.response_auto_resolve })}>
                Save policy
              </Button>
              <span className="meta">
                {form.response_mode === 'automatic' ? 'Automatic controls enabled' : 'Controls require approval'}
                {form.response_auto_resolve ? ' · auto-resolve enabled' : ''}
              </span>
            </div>
          </Card>

          <Card title="Integration webhook" subtitle="Signed, CloudEvents-compatible delivery to SIEM, SOAR, ticketing or a firewall adapter">
            <div className="space-y-3">
              <label className="block space-y-1.5">
                <span className="label">Endpoint</span>
                <Input aria-label="Webhook URL" placeholder="https://soar.example.com/hooks/attacksentry" value={form.webhook_url} onChange={(event) => setForm({ ...form, webhook_url: event.target.value })} />
              </label>
              <label className="block space-y-1.5">
                <span className="label">Signing secret</span>
                <Input type="password" autoComplete="new-password" aria-label="Webhook signing secret" placeholder={settings?.webhook_secret_configured ? 'Secret configured. Enter a value to rotate' : 'At least 16 characters'} value={form.webhook_secret} onChange={(event) => setForm({ ...form, webhook_secret: event.target.value })} />
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" onClick={async () => { await update.mutateAsync({ webhook_url: form.webhook_url, webhook_secret: form.webhook_secret || undefined }); setForm({ ...form, webhook_secret: '' }); setMessage('Integration saved.'); }}>
                  Save integration
                </Button>
                <Button size="sm" variant="secondary" disabled={!settings?.webhook_url} onClick={async () => { const result = await testWebhook.mutateAsync(); setMessage(result.message); }}>
                  Send test event
                </Button>
                {message && <span className="meta">{message}</span>}
              </div>
              <p className="text-[11.5px] leading-5 text-muted-foreground">
                Deliveries are HMAC-SHA256 signed, retried, and never follow redirects. Keep the signing secret in the deployment secret store so it survives a restart.
              </p>
            </div>
          </Card>
        </div>
      )}

      <Card
        title="Response history"
        subtitle="Every request, approval, dispatch, failure and release stays in the audit trail"
        noPadding
        action={<span className="meta">{items.length} records</span>}
      >
        <div className="overflow-x-auto">
          <table className="table-shell min-w-[900px]">
            <thead>
              <tr>
                <th>Status</th>
                <th>Control</th>
                <th>Target</th>
                <th>Mode</th>
                <th>Reason</th>
                <th>Created</th>
                <th className="text-right">Decision</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7}><Skeleton className="h-4 w-full" /></td></tr>
              ) : items.length ? (
                items.map((item) => (
                  <tr key={item.id}>
                    <td><Badge variant={statusVariant(item.status)} dot>{item.status.replace(/_/g, ' ')}</Badge></td>
                    <td className="font-medium">{ACTION_LABEL[item.action] ?? item.action.replace(/_/g, ' ')}</td>
                    <td className="mono text-[12px]" title={item.incident_id}>{item.entity}</td>
                    <td className="capitalize text-muted-foreground">{item.mode}</td>
                    <td className="max-w-[280px] truncate text-muted-foreground">{item.reason}</td>
                    <td>
                      <span className="meta" title={new Date(parseTimestamp(item.created_at)).toLocaleString()}>
                        {relativeTime(parseTimestamp(item.created_at))}
                      </span>
                    </td>
                    <td className="text-right">
                      {item.status === 'pending_approval' && (
                        <div className="flex justify-end gap-1">
                          <Button size="sm" disabled={!isAdmin} onClick={() => decision.mutate({ id: item.id, decision: 'approve' })}>
                            <CheckCircle2 size={14} strokeWidth={1.5} /> Approve
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => decision.mutate({ id: item.id, decision: 'cancel' })} aria-label={`Cancel control for ${item.entity}`}>
                            <XCircle size={14} strokeWidth={1.5} />
                          </Button>
                        </div>
                      )}
                      {ACTIVE_STATUSES.includes(item.status) && (
                        <Button size="sm" variant="outline" disabled={!isAdmin} onClick={() => release(item)}>Release</Button>
                      )}
                      {item.status === 'failed' && <span className="text-[11px] text-severity-critical">{item.provider_message}</span>}
                      {!['pending_approval', ...ACTIVE_STATUSES, 'failed'].includes(item.status) && <span className="meta">—</span>}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7}>
                    <EmptyState
                      icon={Ban}
                      title="No response actions"
                      description="Request containment from an incident, or enable a response policy to let AttackSentry dispatch controls on its own."
                      action={<Button size="sm" variant="outline" onClick={openContain} disabled={!incidents?.length}><Plus size={14} strokeWidth={1.5} /> Contain</Button>}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Dialog open={containOpen} onOpenChange={setContainOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="text-[15px]">Request containment</DialogTitle>
            <DialogDescription className="text-[12px]">
              The incident entity becomes the target. The control needs approval before dispatch and expires at the end of its lifetime.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <label className="block space-y-1.5">
              <span className="label">Target incident</span>
              <Select value={target} onValueChange={setTarget}>
                <SelectTrigger><SelectValue placeholder="Choose an incident" /></SelectTrigger>
                <SelectContent>
                  {(incidents ?? []).map((incident) => (
                    <SelectItem key={incident.id} value={incident.id}>{incident.entity} · {incident.id.slice(0, 8)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
            <label className="block space-y-1.5">
              <span className="label">Action</span>
              <Select value={action} onValueChange={(value) => setAction(value as typeof action)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="isolate_host">Isolate host</SelectItem>
                  <SelectItem value="block_ip">Block IP</SelectItem>
                  <SelectItem value="rate_limit">Rate limit</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label className="block space-y-1.5">
              <span className="label">Lifetime (minutes)</span>
              <Input type="number" min="5" max="10080" value={ttl} onChange={(event) => setTtl(Number(event.target.value))} />
            </label>
            <label className="block space-y-1.5">
              <span className="label">Reason</span>
              <Input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why this target is contained" />
            </label>
            {formError && <p className="text-[11.5px] text-severity-critical">{formError}</p>}
          </div>
          <DialogFooter className="gap-2">
            <Button size="sm" variant="ghost" onClick={() => setContainOpen(false)}>Cancel</Button>
            <Button size="sm" loading={request.isPending} onClick={submitContain}>Request containment</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(releaseTarget)} onOpenChange={(open) => { if (!open) setReleaseTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="text-[15px]">Release containment</DialogTitle>
            <DialogDescription className="text-[12px]">
              This lifts the {releaseTarget ? (ACTION_LABEL[releaseTarget.action] ?? 'containment').toLowerCase() : 'containment'} control on{' '}
              <span className="mono">{releaseTarget?.entity}</span>. The target regains access immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button size="sm" variant="ghost" onClick={() => setReleaseTarget(null)}>Keep containment</Button>
            <Button size="sm" variant="danger" loading={decision.isPending} onClick={confirmRelease}>Release now</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
