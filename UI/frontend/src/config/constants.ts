export const SEVERITY_COLORS = {
  critical: 'hsl(0 72% 51%)',
  high: 'hsl(24 95% 53%)',
  medium: 'hsl(38 92% 50%)',
  low: 'hsl(217 91% 60%)',
  info: 'hsl(220 9% 46%)',
} as const;

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

export const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
] as const;

export const TIME_RANGES = [
  { value: '1h', label: 'Last 1 hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
] as const;

export const SENTRY_MODE_STYLES = {
  active: { label: 'Active', dot: 'bg-primary' },
  monitoring: { label: 'Monitoring', dot: 'bg-muted-foreground' },
  training: { label: 'Training', dot: 'bg-muted-foreground' },
} as const;

export type Severity = keyof typeof SEVERITY_COLORS;
export type SentryMode = keyof typeof SENTRY_MODE_STYLES;
