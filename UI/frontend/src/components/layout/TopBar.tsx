import { useNavigate, useLocation } from 'react-router-dom';
import { useEffect, useRef, useState } from 'react';
import {
  useAuthStore, useAlertStreamStore, useSentryStatusStore, useUIStore,
} from '@/stores';
import { Bell, LogOut, Moon, Sun, Search, ChevronDown, ShieldAlert, Menu, Command } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { parseTimestamp, relativeTime, cn } from '@/lib/utils';

const ROUTE_TITLES: Record<string, string> = {
  '/': 'Overview',
  '/threats': 'Incident queue',
  '/hosts': 'Assets & entities',
  '/network': 'Network analytics',
  '/devices': 'Device control',
  '/response': 'Response center',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

export default function TopBar() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const liveAlerts = useAlertStreamStore((s) => s.liveAlerts);
  const unreadCount = useAlertStreamStore((s) => s.unreadCount);
  const markAllRead = useAlertStreamStore((s) => s.markAllRead);
  const mode = useSentryStatusStore((s) => s.mode);
  const theme = useUIStore((s) => s.theme);
  const setTheme = useUIStore((s) => s.setTheme);
  const setMobileNav = useUIStore((s) => s.setMobileNav);
  const navigate = useNavigate();
  const location = useLocation();
  const [query, setQuery] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, []);

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) {
      navigate(`/hosts?search=${encodeURIComponent(q)}`);
    } else {
      navigate(`/threats?q=${encodeURIComponent(q)}`);
    }
    setQuery('');
  };

  const recent = liveAlerts.slice(0, 6);
  const pageTitle = ROUTE_TITLES[location.pathname] ?? (location.pathname.startsWith('/incidents/') ? 'Incident detail' : location.pathname.startsWith('/alerts/') ? 'Detection detail' : 'Workspace');

  return (
    <header className="sticky top-0 z-30 flex h-[52px] shrink-0 items-center justify-between gap-3 border-b bg-card/95 px-3 backdrop-blur sm:px-5">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setMobileNav(true)} aria-label="Open navigation">
          <Menu size={17} />
        </Button>
        <div className="hidden min-w-0 items-center gap-2 text-[12px] sm:flex">
          <span className="text-muted-foreground">AttackSentry</span>
          <span className="text-muted-foreground/40">/</span>
          <span className="truncate font-medium text-foreground">{pageTitle}</span>
        </div>
        <div className="flex items-center gap-1.5 rounded-md border bg-background px-2 py-1 text-[11px]">
          <span className={cn('h-1.5 w-1.5 rounded-full', mode === 'active' ? 'live-dot bg-primary' : 'bg-severity-medium')} />
          <span className="font-medium capitalize">{mode === 'active' ? 'Active' : mode}</span>
        </div>
        <form onSubmit={submitSearch} className="relative hidden w-full max-w-[340px] lg:block">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search hosts, incidents, detections"
            aria-label="Search hosts, incidents, and detections"
            className="pl-8 pr-14"
          />
          <span className="kbd pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 items-center gap-0.5 lg:flex">
            <Command size={9} /> K
          </span>
        </form>
      </div>

      <div className="flex shrink-0 items-center gap-0.5">
        <Button variant="ghost" size="icon" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title="Toggle theme" aria-label="Toggle theme">
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative" aria-label="Notifications">
              <Bell size={16} />
              {unreadCount > 0 && (
                <span className="absolute right-1 top-1 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-primary px-1 text-[9px] font-semibold text-primary-foreground">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-[340px]">
            <DropdownMenuLabel className="flex items-center justify-between">
              <span>Live detections</span>
              {unreadCount > 0 && (
                <button onClick={markAllRead} className="text-[11px] font-normal text-primary hover:underline">Mark all read</button>
              )}
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {recent.length ? (
              <div className="max-h-72 overflow-y-auto">
                {recent.map((a) => (
                  <button
                    key={a.id}
                    className="flex w-full items-start gap-2.5 rounded-md px-2 py-2 text-left hover:bg-muted"
                    onClick={() => { markAllRead(); navigate(`/alerts/${a.id}`); }}
                  >
                    <ShieldAlert size={14} className="mt-0.5 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[12px] text-foreground">{a.detection_type}</p>
                      <p className="truncate text-[11px] text-muted-foreground">{a.src_ip} · {relativeTime(parseTimestamp(a.timestamp))}</p>
                    </div>
                    <Badge variant={a.severity === 'critical' ? 'destructive' : 'secondary'} className="shrink-0">{a.severity}</Badge>
                  </button>
                ))}
              </div>
            ) : (
              <p className="px-2 py-6 text-center text-[12px] text-muted-foreground">No live detections</p>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="ml-1 flex items-center gap-1.5 rounded-md p-1 text-[12px] hover:bg-muted">
              <Avatar className="h-6 w-6">
                <AvatarFallback className="bg-primary text-[10px] text-primary-foreground">
                  {user?.username?.[0]?.toUpperCase() ?? 'U'}
                </AvatarFallback>
              </Avatar>
              <span className="hidden sm:block">{user?.username}</span>
              <ChevronDown size={12} className="text-muted-foreground" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuLabel>
              <p className="text-[12px]">{user?.full_name || user?.username}</p>
              <p className="text-[11px] font-normal capitalize text-muted-foreground">{user?.role}</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate('/settings')}>Settings</DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => { logout(); navigate('/login'); }}
            >
              <LogOut size={14} /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
