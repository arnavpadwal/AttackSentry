import { cn } from '@/lib/utils';

interface StatusDotProps {
  status: 'online' | 'degraded' | 'offline' | 'unknown';
  label?: string;
  size?: 'sm' | 'md';
}

const dotColors = {
  online: 'bg-primary',
  degraded: 'bg-muted-foreground',
  offline: 'bg-muted-foreground/50',
  unknown: 'bg-muted-foreground/40',
};

export default function StatusDot({ status, label, size = 'md' }: StatusDotProps) {
  const dotSize = size === 'sm' ? 'h-2 w-2' : 'h-2.5 w-2.5';
  return (
    <span className="inline-flex items-center gap-2">
      <span className={cn('relative inline-flex rounded-full', dotSize, dotColors[status])} />
      {label && <span className="text-xs text-muted-foreground">{label}</span>}
    </span>
  );
}
