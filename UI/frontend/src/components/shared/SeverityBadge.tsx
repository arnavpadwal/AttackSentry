import { cn } from '@/lib/utils';
import type { Severity } from '@/config/constants';

const dot: Record<string, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-severity-info',
};

const label: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

interface SeverityBadgeProps {
  severity: string | null | undefined;
  className?: string;
  /** Show the word after the dot. Off for dense tables that already have a column. */
  withLabel?: boolean;
}

/**
 * Severity is a dot and a word, sized to sit inside a row. Never a filled
 * alert-colored pill.
 */
export default function SeverityBadge({ severity, className, withLabel = true }: SeverityBadgeProps) {
  const key = (severity ?? 'info').toLowerCase();
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 text-[11px] font-medium text-foreground/85', className)}
      title={label[key] ?? key}
    >
      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', dot[key] ?? dot.info)} aria-hidden />
      {withLabel && <span className="capitalize">{label[key] ?? key}</span>}
    </span>
  );
}

export { dot as severityDot };

export function severityClass(severity: string | null | undefined): string {
  const key = (severity ?? 'info').toLowerCase() as Severity;
  return `rail-${key}`;
}
