import { cn } from "../../lib/cn";

interface LoadingStateProps {
  className?: string;
  rows?: number;
}

/** A restrained skeleton-pulse placeholder used inside cards/charts/tables while loading. */
export function LoadingState({ className, rows = 3 }: LoadingStateProps) {
  return (
    <div className={cn("flex flex-col gap-3 py-2", className)} role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="h-3 animate-pulse rounded-full bg-surface-raised"
          style={{ width: `${85 - i * 12}%` }}
        />
      ))}
    </div>
  );
}

/** Full-panel loading state for charts/large surfaces where a skeleton bar list doesn't fit. */
export function LoadingPanel({ className }: { className?: string }) {
  return (
    <div
      className={cn("flex h-full min-h-[220px] w-full items-center justify-center", className)}
      role="status"
      aria-label="Loading"
    >
      <div className="flex items-center gap-2.5 text-text-muted">
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-border-strong border-t-primary" />
        <span className="text-xs font-medium">Loading data…</span>
      </div>
    </div>
  );
}
