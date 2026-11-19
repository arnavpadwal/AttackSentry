import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';
import { Button as UIButton } from '@/components/ui/button';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'outline' | 'link';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  loading?: boolean;
}

const variantMap: Record<string, 'default' | 'secondary' | 'ghost' | 'destructive' | 'outline' | 'link'> = {
  primary: 'default',
  secondary: 'secondary',
  ghost: 'ghost',
  danger: 'destructive',
  outline: 'outline',
  link: 'link',
};

const sizeMap: Record<string, 'default' | 'sm' | 'lg' | 'icon'> = {
  sm: 'sm',
  md: 'default',
  lg: 'lg',
  icon: 'icon',
};

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', loading, children, className, disabled, ...props }, ref) => {
    return (
      <UIButton
        ref={ref}
        variant={variantMap[variant] ?? 'default'}
        size={sizeMap[size] ?? 'default'}
        className={cn(className)}
        disabled={disabled || loading}
        {...props}
      >
        {loading && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />}
        {children}
      </UIButton>
    );
  }
);

Button.displayName = 'Button';
export default Button;
