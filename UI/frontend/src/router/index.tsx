import { createBrowserRouter } from 'react-router-dom';
import { ProtectedRoute } from './ProtectedRoute';
import App from '@/App';
import LoginPage from '@/pages/LoginPage';
import OverviewPage from '@/pages/OverviewPage';
import ThreatFeedPage from '@/pages/ThreatFeedPage';
import AlertDetailPage from '@/pages/AlertDetailPage';
import IncidentDetailPage from '@/pages/IncidentDetailPage';
import HostsPage from '@/pages/HostsPage';
import HostDetailPage from '@/pages/HostDetailPage';
import DevicesPage from '@/pages/DevicesPage';
import NetworkMapPage from '@/pages/NetworkMapPage';
import ReportsPage from '@/pages/ReportsPage';
import SettingsPage from '@/pages/SettingsPage';
import ResponsePage from '@/pages/ResponsePage';
import NotFoundPage from '@/pages/NotFoundPage';

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: (
      <ProtectedRoute>
        <App />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'threats', element: <ThreatFeedPage /> },
      { path: 'alerts/:id', element: <AlertDetailPage /> },
      { path: 'incidents/:id', element: <IncidentDetailPage /> },
      { path: 'hosts', element: <HostsPage /> },
      { path: 'hosts/:id', element: <HostDetailPage /> },
      { path: 'devices', element: <DevicesPage /> },
      { path: 'response', element: <ResponsePage /> },
      { path: 'network', element: <NetworkMapPage /> },
      { path: 'reports', element: <ReportsPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]);
