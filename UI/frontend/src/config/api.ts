// Same-origin by default: Vite proxies /api and /ws in development and nginx
// proxies them in production. Override only when the API lives on another host.
const configuredApi = import.meta.env.VITE_API_URL as string | undefined;
const configuredWs = import.meta.env.VITE_WS_URL as string | undefined;

export const API_BASE = configuredApi ?? '';

export const WS_BASE =
  configuredWs ??
  `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;
