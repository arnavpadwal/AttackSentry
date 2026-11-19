import { create } from 'zustand';
import type { User } from '@/types';
import { api } from '@/lib/axios';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  sessionChecked: boolean;  // true once /auth/me has been attempted
  login: (user: User) => void;
  logout: () => void;
  checkSession: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  sessionChecked: false,

  login: (user) => set({ user, isAuthenticated: true, sessionChecked: true }),

  logout: async () => {
    try { await api.post('/api/auth/logout'); } catch { /* ignore */ }
    set({ user: null, isAuthenticated: false, sessionChecked: true });
  },

  checkSession: async () => {
    try {
      const { data } = await api.get('/api/auth/me');
      set({ user: data, isAuthenticated: true, sessionChecked: true });
    } catch {
      set({ user: null, isAuthenticated: false, sessionChecked: true });
    }
  },
}));
