import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface PageHeaderProps {
  title: string;
  description?: string;
  meta?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

/**
 * One page header for the whole console: title, one line of context, actions
 * on the same baseline. Sentence case only.
 */
export default function PageHeader({ title, description, meta, actions, className }: PageHeaderProps) {
  return (
    <header className={cn('flex flex-wrap items-start justify-between gap-3', className)}>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="page-title">{title}</h1>
          {meta}
        </div>
        {description && <p className="page-subtitle max-w-[72ch]">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
