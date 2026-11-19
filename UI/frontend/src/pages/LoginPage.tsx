import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Radar, BrainCircuit, BellRing } from 'lucide-react';
import { api } from '@/lib/axios';
import { useAuthStore } from '@/stores';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { User } from '@/types';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const login = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/api/auth/login', { username, password });
      login(data.user as User);
      navigate('/');
    } catch (err: any) {
      setError(err?.response
        ? (err.response.data?.detail ?? 'Invalid credentials')
        : 'Backend unavailable — start the AttackSentry API and try again');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-background">
      <div className="relative hidden w-[46%] flex-col justify-between border-r bg-card p-10 lg:flex">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground"><Shield size={16} strokeWidth={2.2} /></div>
          <div>
            <p className="text-[13px] font-semibold tracking-tight text-foreground">AttackSentry</p>
            <p className="text-[10px] font-medium tracking-wide text-muted-foreground">Network Detection & Response</p>
          </div>
        </div>

        <div className="max-w-sm">
          <h1 className="text-[28px] font-semibold leading-tight tracking-tight text-foreground">Know what changed.<br />Know what to do.</h1>
          <p className="mt-4 text-[12px] leading-6 text-muted-foreground">
            Environment-aware anomaly detection, expert attribution, and an auditable response workspace for the first fifteen minutes of an incident.
          </p>
          <div className="mt-8 space-y-4 border-t pt-6">
            {[
              { icon: Radar, title: 'Environment baseline', desc: 'Per-host, per-subnet, and global models learn normal.' },
              { icon: BrainCircuit, title: 'Expert attribution', desc: 'Five specialised models produce one calibrated verdict.' },
              { icon: BellRing, title: 'Batched AI triage', desc: 'One evidence dossier per incident, rate-limit aware.' },
            ].map((f) => (
              <div key={f.title} className="flex items-start gap-3">
                <f.icon size={15} className="mt-0.5 shrink-0 text-primary" />
                <div>
                  <p className="text-[12px] font-medium text-foreground">{f.title}</p>
                  <p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
          <span>© 2026 AttackSentry</span>
          <span className="mono">v1.0.0</span>
        </div>
      </div>

      <div className="flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-[340px]">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground"><Shield size={18} /></div>
            <div><p className="text-[14px] font-semibold">AttackSentry</p><p className="text-[10px] text-muted-foreground">NDR Console</p></div>
          </div>

          <div>
            <h2 className="text-[20px] font-semibold tracking-tight">Sign in</h2>
            <p className="mt-1 text-[12px] text-muted-foreground">Use the credentials issued by your administrator.</p>
          </div>

          <form onSubmit={onSubmit} className="mt-6 space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="username">Username</Label>
              <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
            </div>
            {error && <p className="rounded-sm border border-destructive/30 bg-destructive/[0.06] px-2.5 py-2 text-[11px] text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading} size="lg">{loading ? 'Signing in…' : 'Sign in'}</Button>
          </form>

          <div className="mt-8 border-t pt-4 text-[10px] leading-5 text-muted-foreground">
            <p>Authorized access only. Sessions are logged and audited.</p>
            <p className="mt-1">For access issues, contact your security operations administrator.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
