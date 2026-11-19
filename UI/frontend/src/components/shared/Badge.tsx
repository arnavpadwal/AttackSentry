import { cn } from '@/lib/utils';
import type { Severity } from '@/config/constants';

interface BadgeProps {
  children: React.ReactNode;
  variant?: Severity | 'default' | 'inverse' | 'secondary';
  className?: string;
  dot?: boolean;
}

const severityClasses: Record<string, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
  info: 'bg-severity-info/15 text-severity-info border-severity-info/30',
  default: 'bg-secondary text-secondary-foreground border-transparent',
  secondary: 'bg-secondary text-secondary-foreground border-transparent',
  inverse: 'bg-primary text-primary-foreground border-transparent',
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

export default function Badge({ children, variant = 'default', className, dot }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-[11px] font-medium leading-4',
        severityClasses[variant] ?? severityClasses.default,
        className
      )}
    >
      {dot && <span className={cn('h-1.5 w-1.5 rounded-full', dotColors[variant] ?? dotColors.default)} />}
      {children}
    </span>
  );
}
