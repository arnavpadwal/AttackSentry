import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Radar, BrainCircuit, BellRing, Moon, Sun } from 'lucide-react';
import { api } from '@/lib/axios';
import { useAuthStore, useUIStore } from '@/stores';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { User } from '@/types';

const capabilities = [
  { icon: Radar, title: 'Environment baseline', desc: 'Per-host, per-subnet, and global models learn what normal looks like.' },
  { icon: BrainCircuit, title: 'Expert attribution', desc: 'Five specialised models produce one calibrated verdict.' },
  { icon: BellRing, title: 'Batched AI triage', desc: 'One evidence dossier per incident, with a fallback playbook.' },
];

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const login = useAuthStore((s) => s.login);
  const theme = useUIStore((s) => s.theme);
  const setTheme = useUIStore((s) => s.setTheme);
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
      <aside className="relative hidden w-[55%] flex-col justify-between overflow-hidden border-r bg-card px-10 py-9 lg:flex">
        <svg
          aria-hidden="true"
          viewBox="0 0 600 140"
          preserveAspectRatio="none"
          className="pointer-events-none absolute inset-x-0 bottom-0 h-36 w-full text-primary/10"
        >
          <polyline
            points="0,118 64,118 92,62 120,118 196,118 228,40 260,118 336,118 368,82 400,118 476,118 508,56 540,118 600,118"
            fill="none"
            stroke="currentColor"
            strokeWidth="1"
            vectorEffect="non-scaling-stroke"
          />
        </svg>

        <div className="relative flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md border bg-background">
            <Shield size={16} strokeWidth={1.5} className="text-primary" />
          </div>
          <div>
            <p className="text-[13px] font-semibold text-foreground">AttackSentry</p>
            <p className="text-[11px] text-muted-foreground">On-premises NDR console</p>
          </div>
        </div>

        <div className="relative max-w-[48ch]">
          <h1 className="text-[22px] font-semibold leading-8 tracking-[-0.01em] text-foreground">
            Network detection and response on your own infrastructure.
          </h1>
          <p className="mt-3 text-[12.5px] leading-6 text-muted-foreground">
            A Rust sensor reads L3/L4 flow metadata. The core learns the environment baseline,
            attributes deviations, and correlates them into incidents.
          </p>

          <div className="mt-8 grid gap-4 border-t pt-6">
            {capabilities.map((c) => (
              <div key={c.title} className="flex items-start gap-3">
                <c.icon size={15} strokeWidth={1.5} className="mt-0.5 shrink-0 text-muted-foreground" />
                <div>
                  <p className="text-[12px] font-medium text-foreground">{c.title}</p>
                  <p className="mt-0.5 text-[11.5px] leading-5 text-muted-foreground">{c.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative flex items-center justify-between text-[11px] text-muted-foreground">
          <span>© 2026 AttackSentry</span>
          <span className="mono">v1.0.0</span>
        </div>
      </aside>

      <div className="relative flex flex-1 items-center justify-center px-6 py-14">
        <div className="absolute right-4 top-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={16} strokeWidth={1.5} /> : <Moon size={16} strokeWidth={1.5} />}
          </Button>
        </div>

        <div className="w-full max-w-sm">
          <div className="mb-6 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border bg-card">
              <Shield size={16} strokeWidth={1.5} className="text-primary" />
            </div>
            <div>
              <p className="text-[13px] font-semibold text-foreground">AttackSentry</p>
              <p className="text-[11px] text-muted-foreground">On-premises NDR console</p>
            </div>
          </div>

          <div className="panel p-6">
            <div>
              <h2 className="text-[15px] font-semibold tracking-[-0.01em] text-foreground">Sign in</h2>
              <p className="mt-1 text-[11.5px] leading-5 text-muted-foreground">
                Console access is limited to accounts issued by your administrator.
              </p>
            </div>

            <form onSubmit={onSubmit} className="mt-5 space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="username" className="text-[11px] font-medium text-muted-foreground">Username</Label>
                <Input id="username" className="h-9" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password" className="text-[11px] font-medium text-muted-foreground">Password</Label>
                <Input id="password" className="h-9" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
              </div>
              {error && (
                <p role="alert" className="rounded-md border border-destructive/30 bg-destructive/[0.06] px-2.5 py-2 text-[11.5px] leading-5 text-destructive">
                  {error}
                </p>
              )}
              <Button type="submit" className="w-full" disabled={loading} size="lg">
                {loading ? 'Signing in…' : 'Sign in'}
              </Button>
            </form>
          </div>

          <div className="mt-6 space-y-1 text-[11px] leading-5 text-muted-foreground">
            <p>Authorized access only. Sessions are logged and audited.</p>
            <p>For access issues, contact your security operations administrator.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
