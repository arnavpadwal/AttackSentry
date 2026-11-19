import { cn } from '@/lib/utils';
import type { Severity } from '@/config/constants';

interface BadgeProps {
  children: React.ReactNode;
  variant?: Severity | 'default' | 'inverse' | 'secondary';
  className?: string;
  dot?: boolean;
}

const severityClasses: Record<string, string> = {
  critical: 'bg-severity-critical/10 text-foreground',
  high: 'bg-severity-high/10 text-foreground',
  medium: 'bg-severity-medium/10 text-foreground',
  low: 'bg-severity-low/10 text-foreground',
  info: 'bg-severity-info/10 text-foreground',
  default: 'bg-secondary text-secondary-foreground',
  secondary: 'bg-secondary text-secondary-foreground',
  inverse: 'bg-primary text-primary-foreground',
};

const dotColors: Record<string, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-severity-info',
  default: 'bg-muted-foreground',
  secondary: 'bg-muted-foreground',
  inverse: 'bg-primary-foreground',
};

/**
 * Quiet label. Severity tints the wash and colors one dot; the word stays in
 * the foreground so a wall of rows does not turn into a fruit salad.
 */
export default function Badge({ children, variant = 'default', className, dot }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-[4px] px-1.5 py-0.5 text-[11px] font-medium leading-4',
        severityClasses[variant] ?? severityClasses.default,
        className
      )}
    >
      {dot && <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', dotColors[variant] ?? dotColors.default)} />}
      {children}
    </span>
  );
}
