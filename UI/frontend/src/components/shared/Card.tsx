import { cn } from '@/lib/utils';

interface CardProps {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
}

/**
 * Section surface. One hairline, one radius, a header row that shares the
 * baseline with its action.
 */
export default function Card({ title, subtitle, action, children, className, noPadding }: CardProps) {
  return (
    <section className={cn('panel overflow-hidden', className)}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-[12.5px] font-semibold leading-5 text-foreground">{title}</h2>}
            {subtitle && <p className="truncate text-[11.5px] leading-4 text-muted-foreground">{subtitle}</p>}
          </div>
          {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
        </header>
      )}
      <div className={cn(noPadding ? 'p-0' : 'p-4')}>{children}</div>
    </section>
  );
}
