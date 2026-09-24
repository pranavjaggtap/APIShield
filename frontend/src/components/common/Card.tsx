import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

interface CardProps {
  title?: string;
  description?: string;
  action?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}

/**
 * The base surface used by every panel on the dashboard - consistent border,
 * radius, and background so cards never look randomly styled against each other.
 */
export function Card({ title, description, action, className, bodyClassName, children }: CardProps) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-surface shadow-[0_1px_0_0_rgba(255,255,255,0.02)_inset]",
        className,
      )}
    >
      {(title || action) && (
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div>
            {title && <h3 className="text-sm font-semibold text-text-primary">{title}</h3>}
            {description && <p className="mt-0.5 text-xs text-text-secondary">{description}</p>}
          </div>
          {action}
        </div>
      )}
      <div className={cn("p-5", bodyClassName)}>{children}</div>
    </div>
  );
}
