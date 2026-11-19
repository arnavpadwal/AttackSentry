import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { CheckCircle2, LogOut, Plus, Trash2, UserPlus } from 'lucide-react';
import PageHeader from '@/components/shared/PageHeader';
import Card from '@/components/shared/Card';
import StatusDot from '@/components/shared/StatusDot';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { useAuthStore, useUIStore } from '@/stores';
import {
  useCreateSensor, useCreateSuppression, useCreateUser, useDeleteSuppression, useDeleteUser,
  useSensors, useSettings, useSuppressions, useTestLLM, useUpdateSettings, useUpdateUser, useUsers,
} from '@/queries/settings';
import { api } from '@/lib/axios';
import { cn, parseTimestamp, relativeTime } from '@/lib/utils';
import type { Settings } from '@/types';

type Draft = {
  baseline_hours: string;
  default_alert_threshold: string;
  incident_window_seconds: string;
  suppression_window_seconds: string;
  retention_days: string;
  llm_provider: string;
  llm_base_url: string;
  llm_model: string;
  llm_api_key: string;
  response_mode: Settings['response_mode'];
  response_min_severity: Settings['response_min_severity'];
  response_min_confidence: string;
  response_action: Settings['response_action'];
  response_ttl_minutes: string;
  response_auto_resolve: boolean;
  enforcement_mode: 'simulate' | 'nftables';
  response_max_auto_per_10m: string;
};

const fromSettings = (settings: Settings): Draft => ({
  baseline_hours: String(settings.baseline_hours),
  default_alert_threshold: String(settings.default_alert_threshold),
  incident_window_seconds: String(settings.incident_window_seconds),
  suppression_window_seconds: String(settings.suppression_window_seconds),
  retention_days: String(settings.retention_days),
  llm_provider: settings.llm_provider,
  llm_base_url: settings.llm_base_url,
  llm_model: settings.llm_model,
  llm_api_key: '',
  response_mode: settings.response_mode,
  response_min_severity: settings.response_min_severity,
  response_min_confidence: String(settings.response_min_confidence),
  response_action: settings.response_action,
  response_ttl_minutes: String(settings.response_ttl_minutes),
  response_auto_resolve: settings.response_auto_resolve,
  enforcement_mode: settings.enforcement_mode,
  response_max_auto_per_10m: String(settings.response_max_auto_per_10m),
});

const providerLabel: Record<string, string> = {
  auto: 'Auto: LM Studio, then Ollama',
  lmstudio: 'LM Studio native API',
  ollama: 'Ollama',
  openai: 'OpenAI-compatible',
  groq: 'Groq',
  none: 'Disabled',
};

const responseModeLabel: Record<Settings['response_mode'], string> = {
  disabled: 'Disabled',
  approval: 'Approval required',
  automatic: 'Automatic',
};

const responseActionLabel: Record<Settings['response_action'], string> = {
  dynamic: 'Dynamic, per detection',
  isolate_host: 'Isolate host',
  block_ip: 'Block IP',
  rate_limit: 'Rate limit',
};

const severities: Settings['response_min_severity'][] = ['low', 'medium', 'high', 'critical'];

const formSections = [
  ['detection', 'Detection'],
  ['ai', 'AI triage'],
  ['response', 'Response policy'],
  ['interface', 'Interface'],
  ['account', 'Account'],
] as const;

const managementSections = [
  ['sensors', 'Sensors'],
  ['suppressions', 'Suppressions'],
] as const;

function ValueRow({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 first:pt-0 last:pb-0">
      <dt className="text-[12px] text-muted-foreground">{label}</dt>
      <dd className="text-right text-[12.5px] font-medium tabular-nums text-foreground">
        {value}
        {hint && <span className="ml-2 text-[11px] font-normal text-muted-foreground">{hint}</span>}
      </dd>
    </div>
  );
}

function Field({ label, hint, htmlFor, children }: { label: string; hint?: string; htmlFor?: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlFor} className="text-[12px] font-medium text-foreground">{label}</Label>
      {children}
      {hint && <p className="text-[11px] leading-4 text-muted-foreground">{hint}</p>}
    </div>
  );
}

function NumberField({
  id, label, hint, derived, suffix, value, min, max, step, onChange,
}: {
  id: string; label: string; hint?: string; derived?: string; suffix: string; value: string;
  min?: number; max?: number; step?: number; onChange: (value: string) => void;
}) {
  return (
    <Field label={label} hint={hint} htmlFor={id}>
      <div className="flex items-center gap-2">
        <Input
          id={id}
          type="number"
          inputMode="decimal"
          className="w-32 tabular-nums"
          value={value}
          min={min}
          max={max}
          step={step}
          onChange={(event) => onChange(event.target.value)}
        />
        <span className="meta">{suffix}</span>
      </div>
      {derived && <p className="text-[11px] leading-4 text-muted-foreground">{derived}</p>}
    </Field>
  );
}

function baselineDerived(value: string): string | undefined {
  const hours = Number(value);
  if (!Number.isFinite(hours) || hours <= 0 || hours >= 1) return undefined;
  return `= ${Math.round(hours * 60)} minutes`;
}

export default function SettingsPage() {
  const currentUser = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const theme = useUIStore((s) => s.theme);
  const setTheme = useUIStore((s) => s.setTheme);
  const isAdmin = currentUser?.role === 'admin';

  const { data: settings, isLoading, isError } = useSettings();
  const testLLM = useTestLLM();
  const updateSettings = useUpdateSettings();
  const { data: sensors } = useSensors();
  const createSensor = useCreateSensor();
  const { data: suppressions } = useSuppressions();
  const createSuppression = useCreateSuppression();
  const deleteSuppression = useDeleteSuppression();
  const { data: users } = useUsers(isAdmin);
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();

  const [activeSection, setActiveSection] = useState<string>('detection');
  const [draft, setDraft] = useState<Draft | null>(null);
  const [llmResult, setLlmResult] = useState('');
  const [saveNote, setSaveNote] = useState('');
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'analyst', full_name: '' });
  const [newRule, setNewRule] = useState({ name: '', entity: '', subnet: '', attack_family: '', reason: '' });
  const [passwords, setPasswords] = useState({ current: '', next: '' });
  const [passwordMessage, setPasswordMessage] = useState('');
  const [sensorName, setSensorName] = useState('');
  const [sensorMessage, setSensorMessage] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (settings && !draft) setDraft(fromSettings(settings));
  }, [settings, draft]);

  const setField = <K extends keyof Draft>(key: K, value: Draft[K]) => {
    setDraft((current) => (current ? { ...current, [key]: value } : current));
  };

  const dirty = useMemo(() => {
    if (!settings || !draft) return [] as string[];
    const changed: string[] = [];
    if (draft.baseline_hours !== String(settings.baseline_hours)) changed.push('Baseline window');
    if (draft.default_alert_threshold !== String(settings.default_alert_threshold)) changed.push('Alert threshold');
    if (draft.incident_window_seconds !== String(settings.incident_window_seconds)) changed.push('Incident window');
    if (draft.suppression_window_seconds !== String(settings.suppression_window_seconds)) changed.push('Suppression window');
    if (draft.retention_days !== String(settings.retention_days)) changed.push('Retention');
    if (draft.llm_provider !== settings.llm_provider) changed.push('AI provider');
    if (draft.llm_base_url !== settings.llm_base_url) changed.push('AI base URL');
    if (draft.llm_model !== settings.llm_model) changed.push('AI model');
    if (draft.llm_api_key.trim()) changed.push('AI API key');
    if (draft.response_mode !== settings.response_mode) changed.push('Response mode');
    if (draft.response_min_severity !== settings.response_min_severity) changed.push('Response severity');
    if (draft.response_min_confidence !== String(settings.response_min_confidence)) changed.push('Response confidence');
    if (draft.response_action !== settings.response_action) changed.push('Response action');
    if (draft.response_ttl_minutes !== String(settings.response_ttl_minutes)) changed.push('Response TTL');
    if (draft.response_auto_resolve !== settings.response_auto_resolve) changed.push('Auto-resolve');
    if (draft.enforcement_mode !== settings.enforcement_mode) changed.push('Enforcement adapter');
    if (draft.response_max_auto_per_10m !== String(settings.response_max_auto_per_10m)) changed.push('Automatic action budget');
    return changed;
  }, [settings, draft]);

  const numericBounds: [keyof Draft, number, number][] = [
    ['baseline_hours', 0.05, 720],
    ['default_alert_threshold', 0, 1],
    ['incident_window_seconds', 30, 86400],
    ['suppression_window_seconds', 30, 604800],
    ['retention_days', 1, 3650],
    ['response_min_confidence', 0, 1],
    ['response_ttl_minutes', 5, 10080],
    ['response_max_auto_per_10m', 1, 100],
  ];
  const invalid = draft ? numericBounds.some(([key, min, max]) => {
    const raw = draft[key] as string;
    const value = Number(raw);
    return raw.trim() === '' || !Number.isFinite(value) || value < min || value > max;
  }) : false;
  const canSave = Boolean(isAdmin && draft && settings && dirty.length > 0 && !invalid && draft.llm_provider && !updateSettings.isPending);

  const goTo = (id: string) => {
    setActiveSection(id);
    document.getElementById(`settings-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const onSave = async () => {
    if (!settings || !draft) return;
    const patch: Partial<Settings> & { llm_api_key?: string } = {};
    if (Number(draft.baseline_hours) !== settings.baseline_hours) patch.baseline_hours = Number(draft.baseline_hours);
    if (Number(draft.default_alert_threshold) !== settings.default_alert_threshold) patch.default_alert_threshold = Number(draft.default_alert_threshold);
    if (Number(draft.incident_window_seconds) !== settings.incident_window_seconds) patch.incident_window_seconds = Number(draft.incident_window_seconds);
    if (Number(draft.suppression_window_seconds) !== settings.suppression_window_seconds) patch.suppression_window_seconds = Number(draft.suppression_window_seconds);
    if (Number(draft.retention_days) !== settings.retention_days) patch.retention_days = Number(draft.retention_days);
    if (draft.llm_provider !== settings.llm_provider) patch.llm_provider = draft.llm_provider;
    if (draft.llm_base_url !== settings.llm_base_url) patch.llm_base_url = draft.llm_base_url;
    if (draft.llm_model !== settings.llm_model) patch.llm_model = draft.llm_model;
    if (draft.llm_api_key.trim()) patch.llm_api_key = draft.llm_api_key.trim();
    if (draft.response_mode !== settings.response_mode) patch.response_mode = draft.response_mode;
    if (draft.response_min_severity !== settings.response_min_severity) patch.response_min_severity = draft.response_min_severity;
    if (Number(draft.response_min_confidence) !== settings.response_min_confidence) patch.response_min_confidence = Number(draft.response_min_confidence);
    if (draft.response_action !== settings.response_action) patch.response_action = draft.response_action;
    if (Number(draft.response_ttl_minutes) !== settings.response_ttl_minutes) patch.response_ttl_minutes = Number(draft.response_ttl_minutes);
    if (draft.response_auto_resolve !== settings.response_auto_resolve) patch.response_auto_resolve = draft.response_auto_resolve;
    if (draft.enforcement_mode !== settings.enforcement_mode) patch.enforcement_mode = draft.enforcement_mode;
    if (Number(draft.response_max_auto_per_10m) !== settings.response_max_auto_per_10m) patch.response_max_auto_per_10m = Number(draft.response_max_auto_per_10m);

    try {
      await updateSettings.mutateAsync(patch);
      setSaveNote('Settings saved.');
      setDraft((current) => (current ? { ...current, llm_api_key: '' } : current));
    } catch (error: any) {
      setSaveNote(error?.response?.data?.detail ?? 'Could not save settings.');
    }
  };

  const onReset = () => {
    if (!settings) return;
    setDraft(fromSettings(settings));
    setSaveNote('');
  };

  const onTestLLM = async () => {
    try {
      const result = await testLLM.mutateAsync();
      setLlmResult(result.message);
    } catch (error: any) {
      setLlmResult(error?.response?.data?.detail ?? 'Connection test failed.');
    }
  };

  const navSections = [
    ...formSections,
    ...(isAdmin ? [['access', 'Access & IAM'] as const] : []),
    ...managementSections,
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Settings"
        description="Detection behaviour, AI triage, response policy, and access for this console."
        meta={<Badge variant="secondary" className="capitalize">{currentUser?.role ?? 'viewer'}</Badge>}
      />

      <div className="grid gap-4 lg:grid-cols-[200px_minmax(0,1fr)] lg:items-start">
        <nav
          aria-label="Settings sections"
          className="flex gap-1 overflow-x-auto pb-1 lg:sticky lg:top-16 lg:flex-col lg:overflow-visible lg:pb-0"
        >
          {navSections.map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => goTo(id)}
              className={cn(
                'shrink-0 rounded-[4px] px-2.5 py-1.5 text-left text-[12px] transition-colors',
                activeSection === id
                  ? 'bg-muted font-medium text-foreground'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground'
              )}
            >
              {label}
            </button>
          ))}
        </nav>

        <div className="min-w-0 space-y-4">
          {isLoading ? (
            <Card>
              <div className="space-y-3">
                <Skeleton className="h-4 w-1/3" />
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-2/3" />
              </div>
            </Card>
          ) : isError || !settings ? (
            <Card>
              <p className="text-[12px] text-muted-foreground">Settings could not be loaded. Check the core API and refresh the page.</p>
            </Card>
          ) : (
            <>
              <div className="space-y-4">
                <div id="settings-detection" className="scroll-mt-16">
                  <Card title="Detection" subtitle="Baseline, correlation windows, and alert thresholds">
                    {isAdmin && draft ? (
                      <div className="grid gap-4 sm:grid-cols-2">
                        <NumberField id="baseline-hours" label="Baseline window" hint="Hours of traffic used to learn the environment baseline." derived={baselineDerived(draft.baseline_hours)} suffix="hours" min={0.05} max={720} step={0.05} value={draft.baseline_hours} onChange={(value) => setField('baseline_hours', value)} />
                        <NumberField id="alert-threshold" label="Alert threshold" hint="Minimum score reported as a detection." suffix="0 to 1" min={0} max={1} step={0.01} value={draft.default_alert_threshold} onChange={(value) => setField('default_alert_threshold', value)} />
                        <NumberField id="incident-window" label="Incident window" hint="Detections inside this window correlate into one incident." suffix="seconds" min={30} max={86400} value={draft.incident_window_seconds} onChange={(value) => setField('incident_window_seconds', value)} />
                        <NumberField id="suppression-window" label="Suppression window" hint="Duplicate detections are folded for this long." suffix="seconds" min={30} max={604800} value={draft.suppression_window_seconds} onChange={(value) => setField('suppression_window_seconds', value)} />
                        <NumberField id="retention" label="Retention" hint="How long detections and incidents are kept." suffix="days" min={1} max={3650} value={draft.retention_days} onChange={(value) => setField('retention_days', value)} />
                      </div>
                    ) : (
                      <dl className="divide-y divide-border/60">
                        <ValueRow label="Baseline window" value={settings.baseline_hours} hint="hours" />
                        <ValueRow label="Alert threshold" value={settings.default_alert_threshold} />
                        <ValueRow label="Incident window" value={settings.incident_window_seconds} hint="seconds" />
                        <ValueRow label="Suppression window" value={settings.suppression_window_seconds} hint="seconds" />
                        <ValueRow label="Retention" value={settings.retention_days} hint="days" />
                      </dl>
                    )}
                  </Card>
                </div>

                <div id="settings-ai" className="scroll-mt-16">
                  <Card title="AI triage" subtitle="Provider used to write investigation playbooks for incidents">
                    {isAdmin && draft ? (
                      <div className="space-y-4">
                        <div className="grid gap-4 sm:grid-cols-2">
                          <Field label="Provider" htmlFor="llm-provider" hint="Any OpenAI-compatible server: llama.cpp, LM Studio, vLLM, or a hosted endpoint.">
                            <Select value={draft.llm_provider} onValueChange={(value) => setField('llm_provider', value)}>
                              <SelectTrigger id="llm-provider"><SelectValue placeholder="Provider" /></SelectTrigger>
                              <SelectContent>
                                {Object.entries(providerLabel).map(([value, label]) => (
                                  <SelectItem key={value} value={value}>{label}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </Field>
                          <Field label="Base URL" htmlFor="llm-base-url" hint="Leave blank for the provider default.">
                            <Input id="llm-base-url" className="mono" placeholder="http://127.0.0.1:1234" value={draft.llm_base_url} onChange={(event) => setField('llm_base_url', event.target.value)} />
                          </Field>
                          <Field label="Model" htmlFor="llm-model" hint="Exact identifier reported by the provider.">
                            <Input id="llm-model" className="mono" placeholder="Exact model identifier" value={draft.llm_model} onChange={(event) => setField('llm_model', event.target.value)} />
                          </Field>
                          <Field label="API key" htmlFor="llm-api-key" hint="Cloud providers only. Stored server-side; leave blank to keep the current key.">
                            <Input id="llm-api-key" type="password" autoComplete="new-password" placeholder="Leave blank to keep the stored key" value={draft.llm_api_key} onChange={(event) => setField('llm_api_key', event.target.value)} />
                          </Field>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          <Button variant="outline" size="sm" disabled={testLLM.isPending} onClick={onTestLLM}>Test connection</Button>
                          {llmResult && <span className="text-[11px] text-muted-foreground">{llmResult}</span>}
                        </div>
                        <p className="text-[11px] leading-4 text-muted-foreground">
                          AI triage is advisory: it writes the playbook and containment follows the response policy. Requests are batched per incident, and cloud providers receive pseudonymised entities unless sensitive context is explicitly enabled.
                        </p>
                      </div>
                    ) : (
                      <dl className="divide-y divide-border/60">
                        <ValueRow label="Provider" value={providerLabel[settings.llm_provider] ?? settings.llm_provider} />
                        <ValueRow label="Base URL" value={<span className="mono text-[11.5px]">{settings.llm_base_url || 'Default'}</span>} />
                        <ValueRow label="Model" value={<span className="mono text-[11.5px]">{settings.llm_model || 'Default'}</span>} />
                        <ValueRow label="API key" value="Not shown" />
                      </dl>
                    )}
                  </Card>
                </div>

                <div id="settings-response" className="scroll-mt-16">
                  <Card title="Response policy" subtitle="When the console may act on a detection, and for how long">
                    {isAdmin && draft ? (
                      <div className="space-y-4">
                        <div className="grid gap-4 sm:grid-cols-2">
                          <Field label="Mode" htmlFor="response-mode" hint="Approval mode waits for an operator before every containment.">
                            <Select value={draft.response_mode} onValueChange={(value) => setField('response_mode', value as Settings['response_mode'])}>
                              <SelectTrigger id="response-mode"><SelectValue /></SelectTrigger>
                              <SelectContent>
                                {(Object.entries(responseModeLabel) as [Settings['response_mode'], string][]).map(([value, label]) => (
                                  <SelectItem key={value} value={value}>{label}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </Field>
                          <Field label="Action" htmlFor="response-action" hint="Dynamic selects the action for each detection.">
                            <Select value={draft.response_action} onValueChange={(value) => setField('response_action', value as Settings['response_action'])}>
                              <SelectTrigger id="response-action"><SelectValue /></SelectTrigger>
                              <SelectContent>
                                {(Object.entries(responseActionLabel) as [Settings['response_action'], string][]).map(([value, label]) => (
                                  <SelectItem key={value} value={value}>{label}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </Field>
                          <Field label="Minimum severity" htmlFor="response-severity">
                            <Select value={draft.response_min_severity} onValueChange={(value) => setField('response_min_severity', value as Settings['response_min_severity'])}>
                              <SelectTrigger id="response-severity" className="capitalize"><SelectValue /></SelectTrigger>
                              <SelectContent>
                                {severities.map((severity) => (
                                  <SelectItem key={severity} value={severity} className="capitalize">{severity}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </Field>
                          <NumberField id="response-confidence" label="Minimum confidence" hint="Detections below this confidence never trigger containment." suffix="0 to 1" min={0} max={1} step={0.01} value={draft.response_min_confidence} onChange={(value) => setField('response_min_confidence', value)} />
                          <NumberField id="response-ttl" label="Default TTL" hint="Containments expire automatically after this long." suffix="minutes" min={5} max={10080} value={draft.response_ttl_minutes} onChange={(value) => setField('response_ttl_minutes', value)} />
                          <Field label="Enforcement adapter" htmlFor="enforcement-mode" hint="Simulated records the control only. nftables applies it on this host when the service runs as root.">
                            <Select value={draft.enforcement_mode} onValueChange={(value) => setField('enforcement_mode', value as Draft['enforcement_mode'])}>
                              <SelectTrigger id="enforcement-mode"><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="simulate">Simulated (record only)</SelectItem>
                                <SelectItem value="nftables">nftables (this host)</SelectItem>
                              </SelectContent>
                            </Select>
                          </Field>
                          <NumberField id="response-budget" label="Automatic actions per 10 minutes" hint="A storm cannot queue more automatic controls than this." suffix="actions" min={1} max={100} value={draft.response_max_auto_per_10m} onChange={(value) => setField('response_max_auto_per_10m', value)} />
                        </div>
                        <div className="flex items-center justify-between gap-3 rounded-[4px] border px-3 py-2.5">
                          <div>
                            <Label htmlFor="response-auto-resolve" className="text-[12px] font-medium text-foreground">Auto-resolve incidents</Label>
                            <p className="text-[11px] leading-4 text-muted-foreground">Close an incident once its containment expires without a new detection.</p>
                          </div>
                          <Switch id="response-auto-resolve" checked={draft.response_auto_resolve} onCheckedChange={(checked) => setField('response_auto_resolve', checked)} />
                        </div>
                        <p className="text-[11px] leading-4 text-muted-foreground">
                          In approval mode, containment actions wait for an operator. Automatic mode runs them without one.
                        </p>
                        {draft.response_mode === 'automatic' && (
                          <div className="flex items-start gap-2 rounded-[4px] border border-severity-medium/40 bg-severity-medium/10 px-3 py-2">
                            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-severity-medium" />
                            <p className="text-[11px] leading-4 text-foreground/90">
                              Automatic mode is active: matching detections are blocked or isolated without approval.
                              Controls expire after the TTL, are capped by the 10-minute budget, and every action is recorded in Response history.
                            </p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <dl className="divide-y divide-border/60">
                        <ValueRow label="Mode" value={responseModeLabel[settings.response_mode]} />
                        <ValueRow label="Action" value={responseActionLabel[settings.response_action]} />
                        <ValueRow label="Minimum severity" value={<span className="capitalize">{settings.response_min_severity}</span>} />
                        <ValueRow label="Minimum confidence" value={settings.response_min_confidence} />
                        <ValueRow label="Default TTL" value={settings.response_ttl_minutes} hint="minutes" />
                        <ValueRow label="Auto-resolve" value={settings.response_auto_resolve ? 'On' : 'Off'} />
                        <ValueRow label="Enforcement" value={settings.enforcement_mode === 'nftables' ? 'nftables (this host)' : 'Simulated (record only)'} />
                        <ValueRow label="Automatic budget" value={`${settings.response_max_auto_per_10m} per 10 minutes`} />
                      </dl>
                    )}
                  </Card>
                </div>

                <div id="settings-interface" className="scroll-mt-16">
                  <Card title="Interface" subtitle="Appearance of this browser session">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <Label htmlFor="theme-dark" className="text-[12px] font-medium text-foreground">Dark theme</Label>
                        <p className="text-[11px] leading-4 text-muted-foreground">Stored in this browser only. It does not change sensor or detection behaviour.</p>
                      </div>
                      <Switch id="theme-dark" checked={theme === 'dark'} onCheckedChange={(checked) => setTheme(checked ? 'dark' : 'light')} />
                    </div>
                  </Card>
                </div>

                <div id="settings-account" className="scroll-mt-16">
                  <Card title="Account" subtitle="Your identity and session">
                    <dl className="mb-4 divide-y divide-border/60">
                      <ValueRow label="Username" value={<span className="mono text-[11.5px]">{currentUser?.username ?? '—'}</span>} />
                      <ValueRow label="Role" value={<span className="capitalize">{currentUser?.role ?? '—'}</span>} />
                    </dl>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <Field label="Current password" htmlFor="password-current">
                        <Input id="password-current" type="password" autoComplete="current-password" value={passwords.current} onChange={(event) => setPasswords({ ...passwords, current: event.target.value })} />
                      </Field>
                      <Field label="New password" htmlFor="password-next" hint="At least 12 characters.">
                        <Input id="password-next" type="password" autoComplete="new-password" value={passwords.next} onChange={(event) => setPasswords({ ...passwords, next: event.target.value })} />
                      </Field>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={!passwords.current || passwords.next.length < 12}
                        onClick={async () => {
                          try {
                            await api.post('/api/auth/change-password', { current_password: passwords.current, new_password: passwords.next });
                            setPasswords({ current: '', next: '' });
                            setPasswordMessage('Password updated.');
                          } catch (error: any) {
                            setPasswordMessage(error?.response?.data?.detail ?? 'Password update failed.');
                          }
                        }}
                      >
                        Update password
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => logout()}>
                        <LogOut size={14} strokeWidth={1.5} /> Sign out
                      </Button>
                      {passwordMessage && <span className="text-[11px] text-muted-foreground">{passwordMessage}</span>}
                    </div>
                  </Card>
                </div>

                {isAdmin && draft && (
                  <div className="panel sticky bottom-0 z-10 flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                    <div className="min-w-0">
                      <p className="text-[12px] font-medium text-foreground">
                        {dirty.length ? `${dirty.length} unsaved ${dirty.length === 1 ? 'change' : 'changes'}` : 'All settings saved'}
                      </p>
                      <p className="meta truncate">{saveNote || (invalid ? 'Enter a value in range for every numeric field.' : dirty.length ? dirty.slice(0, 3).join(', ') : 'Changes apply to new detections and incidents.')}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" disabled={!dirty.length || updateSettings.isPending} onClick={onReset}>Reset</Button>
                      <Button size="sm" disabled={!canSave} onClick={onSave}>{updateSettings.isPending ? 'Saving' : 'Save changes'}</Button>
                    </div>
                  </div>
                )}
              </div>

              {isAdmin && (
                <div id="settings-access" className="scroll-mt-16">
                  <Card
                    title="Access & IAM"
                    subtitle="Administrators manage analysts and read-only viewers"
                    action={<Badge variant="secondary">{users?.length ?? 0} identities</Badge>}
                    noPadding
                  >
                    <div className="overflow-x-auto">
                      <table className="table-shell">
                        <thead>
                          <tr>
                            <th>Identity</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th className="text-right">Last login</th>
                            <th className="w-10" />
                          </tr>
                        </thead>
                        <tbody>
                          {users?.map((user) => (
                            <tr key={user.id}>
                              <td>
                                <p className="text-[12.5px] font-medium text-foreground">{user.full_name || user.username}</p>
                                <p className="mono text-[11px] text-muted-foreground">{user.username}</p>
                              </td>
                              <td className="text-[11.5px] text-muted-foreground">{user.email}</td>
                              <td>
                                <Select value={user.role} disabled={user.id === currentUser?.id} onValueChange={(role) => updateUser.mutate({ id: user.id, role })}>
                                  <SelectTrigger className="h-7 w-[120px] text-[11.5px] capitalize"><SelectValue /></SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="admin">Administrator</SelectItem>
                                    <SelectItem value="analyst">Analyst</SelectItem>
                                    <SelectItem value="viewer">Viewer</SelectItem>
                                  </SelectContent>
                                </Select>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  aria-pressed={user.is_active}
                                  disabled={user.id === currentUser?.id}
                                  onClick={() => updateUser.mutate({ id: user.id, is_active: !user.is_active })}
                                  className={cn(
                                    'inline-flex items-center gap-1.5 rounded-[4px] border px-1.5 py-0.5 text-[11px] font-medium disabled:opacity-60',
                                    user.is_active ? 'border-primary/30 bg-primary/10 text-foreground' : 'border-border text-muted-foreground'
                                  )}
                                >
                                  <span className={cn('h-1.5 w-1.5 rounded-full', user.is_active ? 'bg-primary' : 'bg-muted-foreground')} />
                                  {user.is_active ? 'Active' : 'Disabled'}
                                </button>
                              </td>
                              <td className="text-right text-[11.5px] tabular-nums text-muted-foreground">{user.last_login ? relativeTime(parseTimestamp(user.last_login)) : 'Never'}</td>
                              <td>
                                <Button variant="ghost" size="icon" className="h-7 w-7" disabled={user.id === currentUser?.id} onClick={() => deleteUser.mutate(user.id)} aria-label={`Delete ${user.username}`}>
                                  <Trash2 size={14} strokeWidth={1.5} />
                                </Button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="border-t p-3">
                      <p className="mb-2 text-[11px] font-medium text-muted-foreground">Add identity</p>
                      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_1fr_120px_auto]">
                        <Input placeholder="Username" value={newUser.username} onChange={(event) => setNewUser({ ...newUser, username: event.target.value })} />
                        <Input placeholder="Email" value={newUser.email} onChange={(event) => setNewUser({ ...newUser, email: event.target.value })} />
                        <Input placeholder="Full name (optional)" value={newUser.full_name} onChange={(event) => setNewUser({ ...newUser, full_name: event.target.value })} />
                        <Input type="password" placeholder="Password (12+ characters)" value={newUser.password} onChange={(event) => setNewUser({ ...newUser, password: event.target.value })} />
                        <Select value={newUser.role} onValueChange={(role) => setNewUser({ ...newUser, role })}>
                          <SelectTrigger className="text-[12px] capitalize"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="analyst">Analyst</SelectItem>
                            <SelectItem value="viewer">Viewer</SelectItem>
                            <SelectItem value="admin">Administrator</SelectItem>
                          </SelectContent>
                        </Select>
                        <Button
                          size="sm"
                          disabled={newUser.username.length < 3 || newUser.email.length < 3 || newUser.password.length < 12 || createUser.isPending}
                          onClick={async () => {
                            try {
                              await createUser.mutateAsync(newUser);
                              setNewUser({ username: '', email: '', password: '', role: 'analyst', full_name: '' });
                              setMessage('Identity created.');
                            } catch (error: any) {
                              setMessage(error?.response?.data?.detail ?? 'Could not create identity.');
                            }
                          }}
                        >
                          <UserPlus size={14} strokeWidth={1.5} /> Add
                        </Button>
                      </div>
                      {message && <p className="mt-2 text-[11px] text-muted-foreground">{message}</p>}
                    </div>
                  </Card>
                </div>
              )}

              <div id="settings-sensors" className="scroll-mt-16">
                <Card
                  title="Sensors"
                  subtitle="Registered capture agents and their connection state"
                  action={isAdmin ? <Badge variant="secondary">{sensors?.length ?? 0} registered</Badge> : undefined}
                  noPadding
                >
                  {isAdmin && (
                    <div className="flex flex-wrap items-center gap-2 border-b p-3">
                      <Input className="w-56" placeholder="Sensor name" value={sensorName} onChange={(event) => setSensorName(event.target.value)} />
                      <Button
                        size="sm"
                        disabled={sensorName.trim().length < 2 || createSensor.isPending}
                        onClick={async () => {
                          try {
                            await createSensor.mutateAsync({ name: sensorName.trim(), sensor_type: 'network' });
                            setSensorName('');
                            setSensorMessage('Sensor registered.');
                          } catch (error: any) {
                            setSensorMessage(error?.response?.data?.detail ?? 'Could not register sensor.');
                          }
                        }}
                      >
                        <Plus size={14} strokeWidth={1.5} /> Register
                      </Button>
                      {sensorMessage && <span className="text-[11px] text-muted-foreground">{sensorMessage}</span>}
                    </div>
                  )}
                  {sensors?.length ? (
                    <div className="overflow-x-auto">
                      <table className="table-shell">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th className="text-right">Flows/s</th>
                            <th className="text-right">Last heartbeat</th>
                            {isAdmin && <th className="text-right">Configuration</th>}
                          </tr>
                        </thead>
                        <tbody>
                          {sensors.map((sensor) => (
                            <tr key={sensor.id}>
                              <td className="text-[12.5px] font-medium text-foreground">{sensor.name}</td>
                              <td className="text-[11.5px] capitalize text-muted-foreground">{sensor.sensor_type}</td>
                              <td><StatusDot status={sensor.status === 'online' ? 'online' : 'offline'} label={sensor.status} size="sm" /></td>
                              <td className="text-right tabular-nums">{sensor.flows_per_second}</td>
                              <td className="text-right text-[11.5px] tabular-nums text-muted-foreground">{sensor.last_heartbeat ? relativeTime(parseTimestamp(sensor.last_heartbeat)) : 'Never'}</td>
                              {isAdmin && (
                                <td className="whitespace-nowrap text-right text-[11.5px]">
                                  <a className="text-primary hover:underline" href={`/api/sensors/${sensor.id}/config?platform=linux`}>Linux</a>
                                  <span className="px-1.5 text-muted-foreground">·</span>
                                  <a className="text-primary hover:underline" href={`/api/sensors/${sensor.id}/config?platform=windows`}>Windows</a>
                                </td>
                              )}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <p className="p-8 text-center text-[12px] text-muted-foreground">No sensors registered.</p>}
                </Card>
              </div>

              <div id="settings-suppressions" className="scroll-mt-16">
                <Card title="Suppressions" subtitle="Scoped exceptions with a business justification" noPadding>
                  {suppressions?.length ? (
                    <ul className="divide-y divide-border">
                      {suppressions.map((rule) => (
                        <li key={rule.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                          <div className="min-w-0">
                            <p className="text-[12.5px] font-medium text-foreground">{rule.name}</p>
                            <p className="truncate text-[11px] text-muted-foreground">
                              {[rule.entity && `entity ${rule.entity}`, rule.subnet && `subnet ${rule.subnet}`, rule.attack_family && `family ${rule.attack_family}`].filter(Boolean).join(' · ') || 'Unscoped'} · {rule.reason}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant={rule.is_active ? 'secondary' : 'muted'}>{rule.is_active ? 'Active' : 'Inactive'}</Badge>
                            {isAdmin && (
                              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => deleteSuppression.mutate(rule.id)} aria-label="Delete rule">
                                <Trash2 size={14} strokeWidth={1.5} />
                              </Button>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : <p className="p-8 text-center text-[12px] text-muted-foreground">No suppression rules.</p>}
                  {isAdmin && (
                    <div className="grid gap-2 border-t p-3 sm:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_1fr_1.3fr_auto]">
                      <Input placeholder="Rule name" value={newRule.name} onChange={(event) => setNewRule({ ...newRule, name: event.target.value })} />
                      <Input placeholder="Entity IP" value={newRule.entity} onChange={(event) => setNewRule({ ...newRule, entity: event.target.value })} />
                      <Input placeholder="Subnet" value={newRule.subnet} onChange={(event) => setNewRule({ ...newRule, subnet: event.target.value })} />
                      <Input placeholder="Attack family" value={newRule.attack_family} onChange={(event) => setNewRule({ ...newRule, attack_family: event.target.value })} />
                      <Input placeholder="Business justification" value={newRule.reason} onChange={(event) => setNewRule({ ...newRule, reason: event.target.value })} />
                      <Button
                        size="sm"
                        disabled={!newRule.name.trim() || newRule.reason.trim().length < 3 || ![newRule.entity, newRule.subnet, newRule.attack_family].some(Boolean)}
                        onClick={() => createSuppression.mutate(newRule)}
                      >
                        Add rule
                      </Button>
                    </div>
                  )}
                  <div className="flex items-center gap-2 border-t px-4 py-2 text-[11px] text-muted-foreground">
                    <CheckCircle2 size={12} strokeWidth={1.5} className="text-primary" /> Suppression is audited; use it for known-good behavior, not to clear active cases.
                  </div>
                </Card>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
