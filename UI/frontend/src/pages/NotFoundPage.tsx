import { Link, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';

export default function NotFoundPage() {
  const { pathname } = useLocation();

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center px-6 py-16 text-center">
      <div className="flex h-9 w-9 items-center justify-center rounded-full border text-muted-foreground">
        <span className="mono text-[11px] leading-none">404</span>
      </div>
      <h1 className="mt-3 text-[15px] font-medium text-foreground">Page not found</h1>
      <p className="mt-1 max-w-[46ch] text-[12px] leading-5 text-muted-foreground">
        This address does not match any page in the console. It may have moved, or the link may be incomplete.
      </p>
      <code className="mono mt-4 max-w-[52ch] truncate rounded-md border bg-muted px-2 py-1 text-[11px] text-muted-foreground">
        {pathname}
      </code>
      <Button asChild variant="outline" size="sm" className="mt-4">
        <Link to="/">Back to Overview</Link>
      </Button>
    </div>
  );
}
