import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import DevicesPage from './DevicesPage';
import type { Device } from '@/types';

const approveMutate = vi.fn();
const rejectMutate = vi.fn();

vi.mock('@/queries/devices', () => ({
  usePendingDevices: () => ({ data: pendingDevices, isLoading: false }),
  useDevices: () => ({ data: [], isLoading: false }),
  useApproveDevice: () => ({ mutate: approveMutate }),
  useRejectDevice: () => ({ mutate: rejectMutate }),
  useUpdateDevice: () => ({ mutate: vi.fn() }),
}));

const makeDevice = (id: string): Device => ({
  id, hostname: `host-${id}`, ip: `10.0.0.${id}`, mac: `00:00:00:00:00:0${id}`,
  os: 'Linux', fingerprint: 'abcdefghijklmnopqrst', status: 'pending',
  whitelist: [], blacklist: [], timeout_hours: null, first_seen: Date.now() / 1000,
  approved_at: null, parent_device_id: null, custom_tag: null, approval_caveat: null,
});

let pendingDevices: Device[] = [];

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <DevicesPage />
    </QueryClientProvider>,
  );
}

describe('DevicesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    pendingDevices = [makeDevice('1'), makeDevice('2')];
  });

  it('renders Approve and Reject buttons for each pending device', () => {
    renderPage();
    expect(screen.getAllByRole('button', { name: /approve/i })).toHaveLength(2);
    expect(screen.getAllByRole('button', { name: /reject/i })).toHaveLength(2);
  });

  it('calls reject mutation with the device id', () => {
    renderPage();
    fireEvent.click(screen.getAllByRole('button', { name: /reject/i })[0]);
    expect(rejectMutate).toHaveBeenCalledWith('1');
  });

  it('calls approve mutation with the device id', () => {
    renderPage();
    fireEvent.click(screen.getAllByRole('button', { name: /approve/i })[1]);
    expect(approveMutate).toHaveBeenCalledWith({ id: '2' });
  });

  it('shows empty state when no devices are pending', () => {
    pendingDevices = [];
    renderPage();
    expect(screen.getByText(/no devices awaiting approval/i)).toBeInTheDocument();
  });
});
