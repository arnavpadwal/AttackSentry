import axios from 'axios';
import { API_BASE } from '@/config/api';

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Refresh once on 401 and retry the original request. Auth endpoints and
// already-retried requests are never looped, and an expired session redirects
// cleanly exactly once.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error.response?.status;
    const original = error.config ?? {};
    const url: string = original.url ?? '';
    if (status !== 401 || original._retried || url.includes('/api/auth/login') || url.includes('/api/auth/refresh')) {
      return Promise.reject(error);
    }
    original._retried = true;
    try {
      await axios.post(`${API_BASE}/api/auth/refresh`, {}, { withCredentials: true });
      return api(original);
    } catch {
      if (window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
      return Promise.reject(error);
    }
  }
);
