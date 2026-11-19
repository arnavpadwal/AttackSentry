import { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuthStore } from '@/stores';
import {
  useCreateSensor, useCreateSuppression, useCreateUser, useDeleteSuppression, useDeleteUser,
  useSensors, useSettings, useSuppressions, useTestLLM, useUpdateSettings, useUpdateUser, useUsers,
} from '@/queries/settings';
import { api } from '@/lib/axios';
import { parseTimestamp, relativeTime, cn } from '@/lib/utils';
import { CheckCircle2, KeyRound, Plus, ShieldCheck, Trash2, UserPlus, Users } from 'lucide-react';

type Tab = 'general' | 'access' | 'sensors' | 'suppressions';

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>('general');
  const currentUser = useAuthStore((s) => s.user);
  const isAdmin = currentUser?.role === 'admin';
  const { data: settings } = useSettings();
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

  const [llmResult, setLLMResult] = useState('');
  const [llmDraft, setLLMDraft] = useState({ provider: '', baseUrl: '', model: '', apiKey: '' });
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'analyst', full_name: '' });
  const [newRule, setNewRule] = useState({ name: '', entity: '', subnet: '', attack_family: '', reason: '' });
  const [passwords, setPasswords] = useState({ current: '', next: '' });
  const [passwordMessage, setPasswordMessage] = useState('');
  const [sensorName, setSensorName] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!settings) return;
    setLLMDraft((current) => current.provider ? current : {
      provider: settings.llm_provider, baseUrl: settings.llm_base_url, model: settings.llm_model, apiKey: '',
    });
  }, [settings]);

  const tabs: Tab[] = isAdmin ? ['general', 'access', 'sensors', 'suppressions'] : ['general', 'sensors', 'suppressions'];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="page-title">Settings</h1>
        <p className="page-subtitle">Identity, sensors, detection integrations, and platform policy.</p>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
        <TabsList className="h-8">
          {tabs.map((t) => (
            <TabsTrigger key={t} value={t} className="h-7 px-3 text-[12px] capitalize">{t === 'access' ? 'Access & IAM' : t}</TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {tab === 'general' && (
        <div className="grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
          <section className="panel">
            <div className="panel-header"><h2 className="panel-title">Detection & AI</h2><Badge variant="outline">Runtime</Badge></div>
            <div className="grid gap-4 p-4 sm:grid-cols-2">
              <div className="space-y-3">
                {[
                  ['Baseline window', `${settings?.baseline_hours ?? '—'} h`],
                  ['Incident window', `${settings?.incident_window_seconds ?? '—'} s`],
                  ['Suppression window', `${settings?.suppression_window_seconds ?? '—'} s`],
                  ['Alert threshold', `${settings?.default_alert_threshold ?? '—'}`],
                  ['Retention', `${settings?.retention_days ?? '—'} days`],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between border-b pb-2 text-[12px] last:border-0 last:pb-0">
                    <span className="text-muted-foreground">{label}</span><span className="font-medium tabular-nums">{value}</span>
                  </div>
                ))}
              </div>
              <div className="space-y-3">
                <p className="section-label">LLM provider</p>
                <Select value={llmDraft.provider} onValueChange={(v) => setLLMDraft({ ...llmDraft, provider: v })}>
                  <SelectTrigger><SelectValue placeholder="Provider" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">Auto: LM Studio, then Ollama</SelectItem>
                    <SelectItem value="lmstudio">LM Studio native API</SelectItem>
                    <SelectItem value="ollama">Ollama</SelectItem>
                    <SelectItem value="openai">OpenAI-compatible</SelectItem>
                    <SelectItem value="groq">Groq</SelectItem>
                    <SelectItem value="none">Disabled</SelectItem>
                  </SelectContent>
                </Select>
                <Input aria-label="LLM endpoint" placeholder="http://127.0.0.1:1234" value={llmDraft.baseUrl} onChange={(e) => setLLMDraft({ ...llmDraft, baseUrl: e.target.value })} />
                <Input aria-label="LLM model" placeholder="Exact model identifier" value={llmDraft.model} onChange={(e) => setLLMDraft({ ...llmDraft, model: e.target.value })} />
                <Input type="password" autoComplete="new-password" aria-label="LLM API key" placeholder="API key (cloud providers only)" value={llmDraft.apiKey} onChange={(e) => setLLMDraft({ ...llmDraft, apiKey: e.target.value })} />
                {isAdmin && (
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" disabled={updateSettings.isPending || !llmDraft.provider} onClick={async () => {
                      try {
                        await updateSettings.mutateAsync({ llm_provider: llmDraft.provider, llm_base_url: llmDraft.baseUrl, llm_model: llmDraft.model, ...(llmDraft.apiKey ? { llm_api_key: llmDraft.apiKey } : {}) });
                        setLLMResult('Configuration saved.');
                      } catch (error: any) { setLLMResult(error?.response?.data?.detail ?? 'Could not save configuration.'); }
                    }}>Save</Button>
                    <Button size="sm" variant="secondary" disabled={testLLM.isPending} onClick={async () => { const r = await testLLM.mutateAsync(); setLLMResult(r.message); }}>Test connection</Button>
                    {llmResult && <span className="self-center text-[11px] text-muted-foreground">{llmResult}</span>}
                  </div>
                )}
                <p className="text-[11px] leading-relaxed text-muted-foreground">AI triage is batched per incident with a bounded queue. Cloud providers receive pseudonymised entities unless sensitive context is explicitly enabled.</p>
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header"><h2 className="panel-title">My account</h2><KeyRound size={14} className="text-muted-foreground" /></div>
            <div className="space-y-3 p-4">
              <div className="flex items-center gap-2 text-[12px]"><Users size={14} className="text-muted-foreground" /><span className="font-medium">{currentUser?.username}</span><Badge variant="secondary" className="capitalize">{currentUser?.role}</Badge></div>
              <Input type="password" autoComplete="current-password" placeholder="Current password" value={passwords.current} onChange={(e) => setPasswords({ ...passwords, current: e.target.value })} />
              <Input type="password" autoComplete="new-password" placeholder="New password (12+ characters)" value={passwords.next} onChange={(e) => setPasswords({ ...passwords, next: e.target.value })} />
              <Button size="sm" disabled={!passwords.current || passwords.next.length < 12} onClick={async () => {
                try { await api.post('/api/auth/change-password', { current_password: passwords.current, new_password: passwords.next }); setPasswords({ current: '', next: '' }); setPasswordMessage('Password updated.'); }
                catch (error: any) { setPasswordMessage(error?.response?.data?.detail ?? 'Password update failed.'); }
              }}>Update password</Button>
              {passwordMessage && <p className="text-[11px] text-muted-foreground">{passwordMessage}</p>}
            </div>
          </section>
        </div>
      )}

      {tab === 'access' && isAdmin && (
        <section className="panel overflow-hidden">
          <div className="panel-header">
            <div><h2 className="panel-title">Users & roles</h2><p className="text-[11px] text-muted-foreground">Administrators manage analysts and read-only viewers.</p></div>
            <Badge variant="outline" className="gap-1"><ShieldCheck size={11} /> {users?.length ?? 0} identities</Badge>
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader><TableRow className="hover:bg-transparent">
                <TableHead>Identity</TableHead><TableHead>Email</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Last login</TableHead><TableHead className="w-10" />
              </TableRow></TableHeader>
              <TableBody>
                {users?.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell><div className="flex items-center gap-2"><span className="flex h-6 w-6 items-center justify-center rounded bg-muted text-[10px] font-semibold uppercase">{u.username.slice(0, 2)}</span><div><p className="text-[12px] font-medium">{u.full_name || u.username}</p><p className="mono text-[10px] text-muted-foreground">{u.username}</p></div></div></TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{u.email}</TableCell>
                    <TableCell>
                      <Select value={u.role} disabled={u.id === currentUser?.id} onValueChange={(role) => updateUser.mutate({ id: u.id, role })}>
                        <SelectTrigger className="h-7 w-[108px] text-[11px] capitalize"><SelectValue /></SelectTrigger>
                        <SelectContent><SelectItem value="admin">Administrator</SelectItem><SelectItem value="analyst">Analyst</SelectItem><SelectItem value="viewer">Viewer</SelectItem></SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell>
                      <button
                        disabled={u.id === currentUser?.id}
                        onClick={() => updateUser.mutate({ id: u.id, is_active: !u.is_active })}
                        className={cn('inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[10px] font-medium disabled:opacity-60', u.is_active ? 'border-primary/30 bg-primary/10 text-primary' : 'border-border text-muted-foreground')}
                      >
                        <span className={cn('h-1.5 w-1.5 rounded-full', u.is_active ? 'bg-primary' : 'bg-muted-foreground')} />{u.is_active ? 'Active' : 'Disabled'}
                      </button>
                    </TableCell>
                    <TableCell className="text-right text-[11px] text-muted-foreground">{u.last_login ? relativeTime(parseTimestamp(u.last_login)) : 'Never'}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="icon" className="h-7 w-7" disabled={u.id === currentUser?.id} onClick={() => deleteUser.mutate(u.id)} aria-label={`Delete ${u.username}`}><Trash2 size={13} /></Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="border-t p-3">
            <p className="mb-2 text-[11px] font-medium text-muted-foreground">Add identity</p>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_1fr_110px_auto]">
              <Input placeholder="Username" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
              <Input placeholder="Email" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} />
              <Input placeholder="Full name (optional)" value={newUser.full_name} onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })} />
              <Input type="password" placeholder="Password (12+ characters)" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
              <Select value={newUser.role} onValueChange={(role) => setNewUser({ ...newUser, role })}>
                <SelectTrigger className="h-8 text-[12px] capitalize"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="analyst">Analyst</SelectItem><SelectItem value="viewer">Viewer</SelectItem><SelectItem value="admin">Administrator</SelectItem></SelectContent>
              </Select>
              <Button size="sm" disabled={newUser.username.length < 3 || newUser.email.length < 3 || newUser.password.length < 12 || createUser.isPending} onClick={async () => {
                try { await createUser.mutateAsync(newUser); setNewUser({ username: '', email: '', password: '', role: 'analyst', full_name: '' }); setMessage('Identity created.'); }
                catch (error: any) { setMessage(error?.response?.data?.detail ?? 'Could not create identity.'); }
              }}><UserPlus size={13} /> Add</Button>
            </div>
            {message && <p className="mt-2 text-[11px] text-muted-foreground">{message}</p>}
          </div>
        </section>
      )}

      {tab === 'sensors' && (
        <section className="panel overflow-hidden">
          <div className="panel-header"><div><h2 className="panel-title">Sensors</h2><p className="text-[11px] text-muted-foreground">Registered capture agents and their connection state.</p></div>{isAdmin && <div className="flex items-center gap-2"><Input className="w-56" placeholder="Sensor name" value={sensorName} onChange={(e) => setSensorName(e.target.value)} /><Button size="sm" disabled={sensorName.trim().length < 2} onClick={async () => { await createSensor.mutateAsync({ name: sensorName.trim(), sensor_type: 'network' }); setSensorName(''); }}><Plus size={13} /> Register</Button></div>}</div>
          {sensors?.length ? (
            <div className="overflow-x-auto"><Table>
              <TableHeader><TableRow className="hover:bg-transparent"><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Flows/s</TableHead><TableHead className="text-right">Last heartbeat</TableHead>{isAdmin && <TableHead className="text-right">Configuration</TableHead>}</TableRow></TableHeader>
              <TableBody>{sensors.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="text-[12px] font-medium">{s.name}</TableCell>
                  <TableCell className="text-[11px] capitalize text-muted-foreground">{s.sensor_type}</TableCell>
                  <TableCell><Badge variant={s.status === 'online' ? 'default' : 'secondary'} className="gap-1 capitalize"><span className={cn('h-1.5 w-1.5 rounded-full', s.status === 'online' ? 'bg-primary-foreground' : 'bg-muted-foreground')} />{s.status}</Badge></TableCell>
                  <TableCell className="text-right text-[11px] tabular-nums">{s.flows_per_second}</TableCell>
                  <TableCell className="text-right text-[11px] text-muted-foreground">{s.last_heartbeat ? relativeTime(parseTimestamp(s.last_heartbeat)) : 'Never'}</TableCell>
                  {isAdmin && <TableCell className="whitespace-nowrap text-right text-[11px]"><a className="text-primary hover:underline" href={`/api/sensors/${s.id}/config?platform=linux`}>Linux</a><span className="px-1.5 text-muted-foreground">·</span><a className="text-primary hover:underline" href={`/api/sensors/${s.id}/config?platform=windows`}>Windows</a></TableCell>}
                </TableRow>
              ))}</TableBody>
            </Table></div>
          ) : <p className="p-8 text-center text-[12px] text-muted-foreground">No sensors registered.</p>}
        </section>
      )}

      {tab === 'suppressions' && (
        <section className="panel overflow-hidden">
          <div className="panel-header"><div><h2 className="panel-title">Suppression rules</h2><p className="text-[11px] text-muted-foreground">Scoped exceptions with a business justification.</p></div></div>
          {suppressions?.length ? (
            <ul className="divide-y">
              {suppressions.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                  <div className="min-w-0"><p className="text-[12px] font-medium">{r.name}</p><p className="truncate text-[11px] text-muted-foreground">{[r.entity && `entity ${r.entity}`, r.subnet && `subnet ${r.subnet}`, r.attack_family && `family ${r.attack_family}`].filter(Boolean).join(' · ') || 'Unscoped'} · {r.reason}</p></div>
                  <div className="flex items-center gap-2"><Badge variant={r.is_active ? 'default' : 'secondary'}>{r.is_active ? 'Active' : 'Inactive'}</Badge>{isAdmin && <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => deleteSuppression.mutate(r.id)} aria-label="Delete rule"><Trash2 size={13} /></Button>}</div>
                </li>
              ))}
            </ul>
          ) : <p className="p-8 text-center text-[12px] text-muted-foreground">No suppression rules.</p>}
          {isAdmin && (
            <div className="grid gap-2 border-t p-3 sm:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_1fr_1.3fr_auto]">
              <Input placeholder="Rule name" value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} />
              <Input placeholder="Entity IP" value={newRule.entity} onChange={(e) => setNewRule({ ...newRule, entity: e.target.value })} />
              <Input placeholder="Subnet" value={newRule.subnet} onChange={(e) => setNewRule({ ...newRule, subnet: e.target.value })} />
              <Input placeholder="Attack family" value={newRule.attack_family} onChange={(e) => setNewRule({ ...newRule, attack_family: e.target.value })} />
              <Input placeholder="Business justification" value={newRule.reason} onChange={(e) => setNewRule({ ...newRule, reason: e.target.value })} />
              <Button size="sm" disabled={!newRule.name.trim() || newRule.reason.trim().length < 3 || ![newRule.entity, newRule.subnet, newRule.attack_family].some(Boolean)} onClick={() => createSuppression.mutate(newRule)}>Add rule</Button>
            </div>
          )}
          <div className="flex items-center gap-2 border-t px-4 py-2 text-[11px] text-muted-foreground"><CheckCircle2 size={12} className="text-primary" /> Suppression is audited; use it for known-good behavior, not to clear active cases.</div>
        </section>
      )}
    </div>
  );
}
