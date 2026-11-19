import { NavLink, useLocation } from 'react-router-dom';
import { useUIStore, useAlertStreamStore, useSentryStatusStore } from '@/stores';
import {
  LayoutDashboard, Siren, Monitor, Network, FileBarChart,
  Settings, ChevronsLeft, ChevronsRight, Shield, Radar, ShieldCheck, X, Server,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const sections: { label: string; items: { to: string; icon: typeof LayoutDashboard; label: string; badge?: boolean }[] }[] = [
  {
    label: 'Operations',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Overview' },
      { to: '/threats', icon: Siren, label: 'Detections', badge: true },
      { to: '/hosts', icon: Monitor, label: 'Assets' },
      { to: '/network', icon: Network, label: 'Network' },
      { to: '/response', icon: ShieldCheck, label: 'Response' },
      { to: '/devices', icon: Server, label: 'Sensors' },
    ],
  },
  {
    label: 'Workspace',
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
          'fixed left-0 top-0 z-50 flex h-screen flex-col border-r bg-sidebar text-sidebar-foreground transition-[width,transform] duration-200',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
          compact ? 'w-[224px] md:w-[52px]' : 'w-[224px]'
        )}
      >
        <div className={cn('flex h-12 shrink-0 items-center gap-2.5 border-b', compact ? 'justify-center px-2' : 'px-3')}>
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[6px] bg-primary text-primary-foreground">
            <Shield size={13} strokeWidth={1.8} />
          </div>
          {!compact && (
            <div className="min-w-0 flex-1">
              <p className="truncate text-[12.5px] font-semibold leading-4 tracking-tight text-foreground">AttackSentry</p>
              <p className="truncate text-[10.5px] leading-3.5 text-muted-foreground">Network detection</p>
            </div>
          )}
          <button
            aria-label="Close navigation"
            className="ml-auto rounded-[6px] p-1 text-muted-foreground hover:bg-muted hover:text-foreground md:hidden"
            onClick={() => setMobileNav(false)}
          >
            <X size={15} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {sections.map((section) => (
            <div key={section.label} className="mb-5 last:mb-0">
              {!compact && (
                <p className="px-2 pb-1.5 text-[11px] font-medium text-muted-foreground/80">{section.label}</p>
              )}
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const isActive = item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to);
                  const link = (
                    <NavLink
                      to={item.to}
                      className={cn(
                        'group relative flex items-center gap-2.5 rounded-[6px] text-[12.5px] transition-colors',
                        compact ? 'h-8 justify-center' : 'h-8 px-2',
                        isActive
                          ? 'bg-muted font-medium text-foreground'
                          : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground'
                      )}
                    >
                      {isActive && !compact && <span className="absolute left-0 top-1.5 h-5 w-[2px] rounded-full bg-primary" />}
                      <item.icon size={16} strokeWidth={1.5} className="shrink-0" />
                      {!compact && <span className="flex-1 truncate">{item.label}</span>}
                      {!compact && item.badge && unreadCount > 0 && (
                        <span className="tabular-nums rounded-[4px] bg-secondary px-1.5 text-[10px] font-medium leading-4 text-secondary-foreground">
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
            <div className="mb-1 flex items-center gap-2 rounded-[6px] px-2 py-1.5">
              <Radar size={14} strokeWidth={1.5} className="shrink-0 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <p className="truncate text-[11.5px] font-medium capitalize leading-4 text-foreground">Engine {mode}</p>
                <p className="truncate text-[10.5px] leading-3.5 text-muted-foreground">Autonomous detection</p>
              </div>
              <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', mode === 'active' ? 'bg-primary live-dot' : 'bg-muted-foreground/50')} />
            </div>
          )}
          <button
            onClick={() => setSidebar(!collapsed)}
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            className="hidden h-7 w-full items-center justify-center rounded-[6px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground md:flex"
          >
            {collapsed ? <ChevronsRight size={14} strokeWidth={1.5} /> : <><ChevronsLeft size={14} strokeWidth={1.5} /><span className="ml-1 text-[11px]">Collapse</span></>}
          </button>
        </div>
      </aside>
    </TooltipProvider>
  );
}
