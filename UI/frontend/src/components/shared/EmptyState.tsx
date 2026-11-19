import type { ElementType, ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface EmptyStateProps {
  icon?: ElementType<{ size?: number | string; className?: string; strokeWidth?: number }>;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

/**
 * Empty is a state, not an accident. It says what would appear here and how
 * to make it appear.
 */
export default function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 py-14 text-center', className)}>
      {Icon && (
        <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-full border text-muted-foreground">
          <Icon size={16} strokeWidth={1.5} />
        </div>
      )}
      <p className="text-[13px] font-medium text-foreground">{title}</p>
      {description && <p className="mt-1 max-w-[46ch] text-[12px] text-muted-foreground">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
