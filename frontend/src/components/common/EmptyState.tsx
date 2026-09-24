import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import { cn } from "../../lib/cn";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  className?: string;
}

/** Shown in place of a table/chart/list when a data source legitimately has no records. */
export function EmptyState({ icon: Icon = Inbox, title, description, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 px-6 py-12 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-border bg-surface-raised">
        <Icon className="h-5 w-5 text-text-muted" strokeWidth={1.75} />
      </div>
      <p className="text-sm font-medium text-text-secondary">{title}</p>
      {description && <p className="max-w-xs text-xs text-text-muted">{description}</p>}
    </div>
  );
}
