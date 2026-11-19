import { useNavigate } from 'react-router-dom';
import { useEffect, useRef, useState } from 'react';
import {
  useAuthStore, useAlertStreamStore, useSentryStatusStore, useUIStore,
} from '@/stores';
import { Bell, LogOut, Moon, Sun, Search, ChevronDown, Menu, Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { parseTimestamp, relativeTime, cn } from '@/lib/utils';
import { severityDot } from '@/components/shared/SeverityBadge';

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

  return (
    <header className="sticky top-0 z-30 flex h-12 shrink-0 items-center justify-between gap-3 border-b bg-background px-3 sm:px-5">
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setMobileNav(true)} aria-label="Open navigation">
          <Menu size={16} strokeWidth={1.5} />
        </Button>

        <form onSubmit={submitSearch} className="relative hidden w-full max-w-[320px] md:block">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" strokeWidth={1.5} />
          <Input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search hosts, detections, incidents"
            aria-label="Search hosts, detections, and incidents"
            className="h-8 bg-card pl-8 pr-12"
          />
          <kbd className="kbd pointer-events-none absolute right-2 top-1/2 hidden min-w-9 -translate-y-1/2 justify-center whitespace-nowrap lg:inline-flex">⌘K</kbd>
        </form>

        <div className="ml-auto flex items-center gap-2 md:ml-1">
          <div className="hidden items-center gap-1.5 rounded-[6px] border px-2 py-1 sm:flex">
            <span className={cn('h-1.5 w-1.5 rounded-full', mode === 'active' ? 'bg-primary live-dot' : 'bg-severity-medium')} />
            <span className="text-[11px] font-medium capitalize leading-4 text-foreground">{mode}</span>
          </div>
          <span className="hidden text-[11px] text-muted-foreground lg:inline">On-premises</span>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-0.5">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun size={16} strokeWidth={1.5} /> : <Moon size={16} strokeWidth={1.5} />}
        </Button>

        <DropdownMenu onOpenChange={(open) => { if (open) markAllRead(); }}>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative" aria-label="Detections">
              <Bell size={16} strokeWidth={1.5} />
              {unreadCount > 0 && (
                <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-severity-critical" />
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-[320px] p-0">
            <DropdownMenuLabel className="flex items-center justify-between px-3 py-2 text-[11px] font-medium text-muted-foreground">
              <span>Live detections</span>
              <span className="tabular-nums">{unreadCount > 0 ? `${unreadCount} new` : 'Up to date'}</span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator className="my-0" />
            {recent.length ? (
              <div className="max-h-72 overflow-y-auto p-1">
                {recent.map((a) => (
                  <button
                    key={a.id}
                    className="flex w-full items-start gap-2.5 rounded-[6px] px-2 py-1.5 text-left hover:bg-muted"
                    onClick={() => navigate(`/alerts/${a.id}`)}
                  >
                    <span className={cn('mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full', severityDot[a.severity] ?? severityDot.info)} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[12px] leading-4 text-foreground">{a.detection_type}</p>
                      <p className="truncate text-[11px] leading-4 text-muted-foreground">{a.src_ip} · {relativeTime(parseTimestamp(a.timestamp))}</p>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <p className="px-3 py-8 text-center text-[11.5px] text-muted-foreground">No live detections</p>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="ml-1 flex items-center gap-1.5 rounded-[6px] p-1 text-[12px] hover:bg-muted">
              <Avatar className="h-6 w-6">
                <AvatarFallback className="bg-secondary text-[10px] font-medium text-secondary-foreground">
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
            <DropdownMenuItem onClick={() => navigate('/settings')}>
              <Settings size={14} strokeWidth={1.5} /> Settings
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => { logout(); navigate('/login'); }}
            >
              <LogOut size={14} strokeWidth={1.5} /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
