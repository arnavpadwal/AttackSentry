import { useEffect, useState } from 'react';
import { Ban, CheckCircle2, Clock3, Link2, ShieldCheck, XCircle } from 'lucide-react';
import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useMitigationDecision, useMitigations } from '@/queries/incidents';
import { useSettings, useTestWebhook, useUpdateSettings } from '@/queries/settings';
import { useAuthStore } from '@/stores';
import { parseTimestamp, relativeTime } from '@/lib/utils';

type ResponseForm = {
  webhook_url: string; webhook_secret: string; webhook_min_severity: 'low' | 'medium' | 'high' | 'critical';
  response_mode: 'disabled' | 'approval' | 'automatic'; response_min_severity: 'low' | 'medium' | 'high' | 'critical';
  response_min_confidence: number; response_action: 'dynamic' | 'isolate_host' | 'block_ip' | 'rate_limit'; response_ttl_minutes: number; response_auto_resolve: boolean;
};

export default function ResponsePage() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';
  const { data: settings } = useSettings();
  const { data: actions } = useMitigations();
  const update = useUpdateSettings();
  const testWebhook = useTestWebhook();
  const decision = useMitigationDecision();
  const [message, setMessage] = useState('');
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

  const pending = actions?.filter((action) => ['pending_approval', 'queued', 'failed'].includes(action.status)).length ?? 0;
  const statusVariant = (status: string) => status === 'failed' ? 'critical' : status === 'dispatched' ? 'low' : status === 'pending_approval' ? 'medium' : 'info';

  return (
    <div className="animate-fade-in space-y-5">
      <div>
        <h1 className="page-title">Response center</h1>
        <p className="page-subtitle">Approve containment requests, tune automation policy, and connect the enforcement plane.</p>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card><div className="flex items-center gap-3"><span className="rounded-lg bg-primary/10 p-2 text-primary"><ShieldCheck size={18} /></span><div><p className="text-xs text-muted-foreground">Policy mode</p><p className="font-semibold capitalize">{settings?.response_mode ?? 'disabled'}</p></div></div></Card>
        <Card><div className="flex items-center gap-3"><span className="rounded-lg bg-muted p-2"><Clock3 size={18} /></span><div><p className="text-xs text-muted-foreground">Needs attention</p><p className="font-semibold">{pending} actions</p></div></div></Card>
        <Card><div className="flex items-center gap-3"><span className="rounded-lg bg-muted p-2"><Link2 size={18} /></span><div><p className="text-xs text-muted-foreground">Enforcement adapter</p><p className="font-semibold">{settings?.webhook_url ? 'Configured' : 'Not configured'}</p></div></div></Card>
      </div>

      {isAdmin && <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Signed integration webhook" subtitle="CloudEvents-compatible delivery for SIEM, SOAR, ticketing, or a firewall adapter">
          <div className="space-y-3">
            <Input aria-label="Webhook URL" placeholder="https://soar.example.com/hooks/attacksentry" value={form.webhook_url} onChange={(event) => setForm({ ...form, webhook_url: event.target.value })} />
            <Input type="password" autoComplete="new-password" aria-label="Webhook signing secret" placeholder={settings?.webhook_secret_configured ? 'Signing secret configured — enter to rotate' : 'Signing secret (16+ characters)'} value={form.webhook_secret} onChange={(event) => setForm({ ...form, webhook_secret: event.target.value })} />
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={async () => { await update.mutateAsync({ webhook_url: form.webhook_url, webhook_secret: form.webhook_secret || undefined }); setForm({ ...form, webhook_secret: '' }); setMessage('Integration settings saved.'); }}>Save integration</Button>
              <Button size="sm" variant="secondary" disabled={!settings?.webhook_url} onClick={async () => { const result = await testWebhook.mutateAsync(); setMessage(result.message); }}>Send test event</Button>
              {message && <span className="text-xs text-muted-foreground">{message}</span>}
            </div>
            <p className="text-xs leading-5 text-muted-foreground">Deliveries are HMAC-SHA256 signed, retried, and never follow redirects. Keep the signing secret in the deployment secret store for restart persistence.</p>
          </div>
        </Card>

        <Card title="Automated response policy" subtitle="Automatic mode dispatches only incidents above both thresholds">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1.5 text-xs text-muted-foreground">Mode<Select value={form.response_mode} onValueChange={(value) => setForm({ ...form, response_mode: value as ResponseForm['response_mode'] })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="disabled">Disabled</SelectItem><SelectItem value="approval">Require approval</SelectItem><SelectItem value="automatic">Automatic</SelectItem></SelectContent></Select></label>
            <label className="space-y-1.5 text-xs text-muted-foreground">Action strategy<Select value={form.response_action} onValueChange={(value) => setForm({ ...form, response_action: value as ResponseForm['response_action'] })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="dynamic">Dynamic by attack type</SelectItem><SelectItem value="isolate_host">Always isolate host</SelectItem><SelectItem value="block_ip">Always block IP</SelectItem><SelectItem value="rate_limit">Always rate limit</SelectItem></SelectContent></Select></label>
            <label className="space-y-1.5 text-xs text-muted-foreground">Minimum severity<Select value={form.response_min_severity} onValueChange={(value) => setForm({ ...form, response_min_severity: value as ResponseForm['response_min_severity'] })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="critical">Critical</SelectItem></SelectContent></Select></label>
            <label className="space-y-1.5 text-xs text-muted-foreground">Minimum confidence<Input type="number" min="0" max="1" step="0.05" value={form.response_min_confidence} onChange={(event) => setForm({ ...form, response_min_confidence: Number(event.target.value) })} /></label>
            <label className="space-y-1.5 text-xs text-muted-foreground">Control lifetime (minutes)<Input type="number" min="5" max="10080" value={form.response_ttl_minutes} onChange={(event) => setForm({ ...form, response_ttl_minutes: Number(event.target.value) })} /></label>
            <label className="flex items-center gap-2 self-end pb-2 text-xs text-muted-foreground"><input type="checkbox" checked={form.response_auto_resolve} onChange={(event) => setForm({ ...form, response_auto_resolve: event.target.checked })} /> Auto-resolve after successful mitigation</label>
          </div>
          <div className="mt-4 flex items-center gap-3"><Button size="sm" onClick={() => update.mutate({ response_mode: form.response_mode, response_action: form.response_action, response_min_severity: form.response_min_severity, response_min_confidence: form.response_min_confidence, response_ttl_minutes: form.response_ttl_minutes, response_auto_resolve: form.response_auto_resolve })}>Save response policy</Button>{form.response_mode === 'automatic' && <Badge variant="high">Automatic controls enabled</Badge>}{form.response_auto_resolve && <Badge variant="medium">Auto-resolve enabled</Badge>}</div>
        </Card>
      </div>}

      <Card title="Mitigation activity" subtitle="Every request, approval, dispatch, failure, and cancellation is retained in the audit trail" noPadding>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[780px]">
            <thead><tr className="border-b"><th className="table-header-cell text-left">Status</th><th className="table-header-cell text-left">Control</th><th className="table-header-cell text-left">Target</th><th className="table-header-cell text-left">Mode</th><th className="table-header-cell text-left">Reason</th><th className="table-header-cell text-right">Created</th><th className="table-header-cell text-right">Decision</th></tr></thead>
            <tbody>{actions?.length ? actions.map((action) => <tr key={action.id} className="border-b last:border-0"><td className="px-5 py-3"><Badge variant={statusVariant(action.status)}>{action.status.replace(/_/g, ' ')}</Badge></td><td className="px-5 py-3 text-sm font-medium">{action.action.replace(/_/g, ' ')}</td><td className="px-5 py-3 font-mono text-xs">{action.entity}</td><td className="px-5 py-3 text-sm capitalize text-muted-foreground">{action.mode}</td><td className="max-w-[280px] truncate px-5 py-3 text-xs text-muted-foreground">{action.reason}</td><td className="px-5 py-3 text-right text-xs text-muted-foreground">{relativeTime(parseTimestamp(action.created_at))}</td><td className="px-5 py-3 text-right">{action.status === 'pending_approval' && <div className="flex justify-end gap-1"><Button size="sm" disabled={!isAdmin} onClick={() => decision.mutate({ id: action.id, decision: 'approve' })}><CheckCircle2 size={14} /> Approve</Button><Button size="sm" variant="ghost" onClick={() => decision.mutate({ id: action.id, decision: 'cancel' })}><XCircle size={14} /></Button></div>}{['dispatched', 'release_failed'].includes(action.status) && <Button size="sm" variant="outline" disabled={!isAdmin} onClick={() => decision.mutate({ id: action.id, decision: 'release' })}>Release now</Button>}{action.status === 'failed' && <span className="text-xs text-destructive">{action.provider_message}</span>}</td></tr>) : <tr><td colSpan={7} className="py-12 text-center"><Ban className="mx-auto mb-2 text-muted-foreground" size={22} /><p className="text-sm font-medium">No mitigation actions</p><p className="mt-1 text-xs text-muted-foreground">Request containment from an incident or enable a response policy.</p></td></tr>}</tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
