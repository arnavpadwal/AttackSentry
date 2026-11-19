export enum Routes {
  LOGIN = '/login',
  OVERVIEW = '/',
  THREATS = '/threats',
  ALERT_DETAIL = '/alerts/:id',
  HOSTS = '/hosts',
  HOST_DETAIL = '/hosts/:id',
  DEVICES = '/devices',
  NETWORK = '/network',
  REPORTS = '/reports',
  SETTINGS = '/settings',
}

export function alertDetailPath(id: string): string {
  return `/alerts/${id}`;
}

export function hostDetailPath(id: string): string {
  return `/hosts/${id}`;
}
