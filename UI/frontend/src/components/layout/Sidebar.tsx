import { NavLink, useLocation } from 'react-router-dom';
import { useUIStore, useAlertStreamStore, useSentryStatusStore } from '@/stores';
import {
  LayoutDashboard, Siren, Monitor, Server, Network, FileBarChart,
  Settings, ChevronLeft, ChevronRight, Shield, Radar, ShieldCheck, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const sections: { label: string; items: { to: string; icon: typeof LayoutDashboard; label: string; badge?: boolean }[] }[] = [
  {
    label: 'Operations',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Overview' },
      { to: '/threats', icon: Siren, label: 'Incident queue', badge: true },
      { to: '/hosts', icon: Monitor, label: 'Assets & entities' },
      { to: '/network', icon: Network, label: 'Network analytics' },
      { to: '/devices', icon: Server, label: 'Device control' },
      { to: '/response', icon: ShieldCheck, label: 'Response center' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { to: '/reports', icon: FileBarChart, label: 'Reports' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export default function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const setSidebar = useUIStore((s) => s.setSidebar);
  const mobileOpen = useUIStore((s) => s.mobileNavOpen);
  const setMobileNav = useUIStore((s) => s.setMobileNav);
  const unreadCount = useAlertStreamStore((s) => s.unreadCount);
  const mode = useSentryStatusStore((s) => s.mode);
  const location = useLocation();
  const compact = collapsed && !mobileOpen;

  return (
    <TooltipProvider delayDuration={0}>
      {mobileOpen && (
        <button
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={() => setMobileNav(false)}
        />
      )}
      <aside
        className={cn(
          'fixed left-0 top-0 z-50 flex h-screen flex-col border-r text-sidebar-foreground transition-all duration-200',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
          compact ? 'w-[232px] md:w-14' : 'w-[232px]'
        )}
        style={{ backgroundColor: 'hsl(var(--sidebar))' }}
      >
        <div className={cn('flex h-[52px] shrink-0 items-center gap-2.5 border-b', compact ? 'justify-center px-2' : 'px-4')}>
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Shield size={15} strokeWidth={2.2} />
          </div>
          {!compact && (
            <div className="min-w-0">
              <p className="truncate text-[13px] font-semibold tracking-tight text-foreground">AttackSentry</p>
              <p className="text-[10px] font-medium tracking-wide text-muted-foreground">NDR Console</p>
            </div>
          )}
          <button
            aria-label="Close navigation"
            className="ml-auto rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground md:hidden"
            onClick={() => setMobileNav(false)}
          >
            <X size={16} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {sections.map((section) => (
            <div key={section.label} className="mb-4">
              {!compact && (
                <p className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/70">
                  {section.label}
                </p>
              )}
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const isActive = item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to);
                  const link = (
                    <NavLink
                      to={item.to}
                      className={cn(
                        'group relative flex items-center gap-2.5 rounded-md text-[12.5px] transition-colors',
                        compact ? 'justify-center px-0 py-2' : 'px-2.5 py-[7px]',
                        isActive
                          ? 'bg-primary/10 text-primary'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                      )}
                    >
                      <item.icon size={16} className={cn('shrink-0', isActive ? 'text-primary' : 'text-muted-foreground')} />
                      {!compact && <span className="flex-1 truncate font-medium">{item.label}</span>}
                      {!compact && item.badge && unreadCount > 0 && (
                        <span className="flex h-4 min-w-4 items-center justify-center rounded-sm bg-primary px-1 text-[9px] font-semibold text-primary-foreground">
                          {unreadCount > 99 ? '99+' : unreadCount}
                        </span>
                      )}
                    </NavLink>
                  );
                  return compact ? (
                    <Tooltip key={item.to}>
                      <TooltipTrigger asChild>{link}</TooltipTrigger>
                      <TooltipContent side="right">{item.label}</TooltipContent>
                    </Tooltip>
                  ) : (
                    <div key={item.to}>{link}</div>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="shrink-0 border-t p-2">
          {!compact && (
            <div className="mb-2 flex items-center gap-2 rounded-md bg-muted/60 px-2.5 py-2">
              <Radar size={14} className={cn(mode === 'active' ? 'text-primary' : 'text-muted-foreground')} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-[11px] font-medium text-foreground">Engine {mode}</p>
                <p className="truncate text-[10px] text-muted-foreground">Autonomous detection</p>
              </div>
              <span className={cn('h-1.5 w-1.5 rounded-full', mode === 'active' ? 'live-dot bg-primary' : 'bg-muted-foreground/50')} />
            </div>
          )}
          <button
            onClick={() => setSidebar(!collapsed)}
            className="hidden w-full items-center justify-center gap-1.5 rounded-md py-1.5 text-[11px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground md:flex"
          >
            {collapsed ? <ChevronRight size={14} /> : <><ChevronLeft size={14} /><span>Collapse</span></>}
          </button>
        </div>
      </aside>
    </TooltipProvider>
  );
}
