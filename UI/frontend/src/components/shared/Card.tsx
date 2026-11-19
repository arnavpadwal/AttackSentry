import { cn } from '@/lib/utils';
import { Card as UICard, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';

interface CardProps {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
}

export default function Card({ title, subtitle, action, children, className, noPadding }: CardProps) {
  return (
    <UICard className={cn('bg-card', className)}>
      {(title || action) && (
        <CardHeader className="flex-row items-center justify-between space-y-0 p-4">
          <div>
            {title && <CardTitle className="text-sm">{title}</CardTitle>}
            {subtitle && <CardDescription className="mt-0.5 text-xs">{subtitle}</CardDescription>}
          </div>
          {action}
        </CardHeader>
      )}
      <CardContent className={cn(noPadding ? 'p-0' : 'p-4', !title && !action && 'pt-4')}>
        {children}
      </CardContent>
    </UICard>
  );
}
