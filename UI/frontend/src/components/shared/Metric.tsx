import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface MetricProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  /** Quiet tone for the figure when the number itself carries meaning. */
  tone?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'ok';
  className?: string;
}

const toneClass: Record<NonNullable<MetricProps['tone']>, string> = {
  default: 'text-foreground',
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  medium: 'text-severity-medium',
  low: 'text-severity-low',
  ok: 'text-primary',
};

/**
 * A stat is a label, a figure and what it refers to. No sparkline, no icon.
 */
export default function Metric({ label, value, hint, tone = 'default', className }: MetricProps) {
  return (
    <div className={cn('panel px-5 py-4', className)}>
      <p className="label">{label}</p>
      <p className={cn('figure mt-1.5', toneClass[tone])}>{value}</p>
      {hint && <p className="meta mt-1 truncate">{hint}</p>}
    </div>
  );
}
