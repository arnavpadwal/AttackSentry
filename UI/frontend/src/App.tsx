import { Outlet, useLocation } from 'react-router-dom';
import { useEffect, useRef } from 'react';
import { useUIStore } from '@/stores';
import { useTelemetry } from '@/hooks/useTelemetry';
import { useAlertStream } from '@/hooks/useAlertStream';
import { useSentryStatus } from '@/queries/sentry';
import Sidebar from '@/components/layout/Sidebar';
import TopBar from '@/components/layout/TopBar';

const scrollPositions: Record<string, number> = {};

function App() {
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);
  const location = useLocation();
  const mainRef = useRef<HTMLDivElement>(null);

  useTelemetry();
  useAlertStream();
  // Keep the shell (engine mode, notifications) current on every route.
  useSentryStatus();

  useEffect(() => {
    const main = mainRef.current;
    if (!main) return;
    const handleScroll = () => { scrollPositions[location.pathname] = main.scrollTop; };
    main.addEventListener('scroll', handleScroll, { passive: true });
    return () => main.removeEventListener('scroll', handleScroll);
  }, [location.pathname]);

  useEffect(() => {
    const main = mainRef.current;
    if (!main) return;
    const savedPos = scrollPositions[location.pathname] ?? 0;
    setTimeout(() => { main.scrollTop = savedPos; }, 10);
  }, [location.pathname]);

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div
        className={sidebarCollapsed
          ? 'flex flex-1 flex-col overflow-hidden transition-[margin] duration-200 md:ml-14'
          : 'flex flex-1 flex-col overflow-hidden transition-[margin] duration-200 md:ml-[232px]'}
      >
        <TopBar />
        <main ref={mainRef} className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1680px] px-4 py-5 sm:px-6 lg:px-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
