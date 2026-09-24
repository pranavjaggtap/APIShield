import { AlertTriangle, RotateCw } from "lucide-react";
import { cn } from "../../lib/cn";

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
  className?: string;
}

/** Shown when a data source fails to load. Always offers a way forward, never a dead end. */
export function ErrorState({ message, onRetry, className }: ErrorStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 px-6 py-12 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-danger/20 bg-danger/10">
        <AlertTriangle className="h-5 w-5 text-danger" strokeWidth={1.75} />
      </div>
      <div>
        <p className="text-sm font-medium text-text-primary">Unable to load data</p>
        <p className="mt-1 max-w-xs text-xs text-text-muted">{message}</p>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-1 inline-flex items-center gap-1.5 rounded-md border border-border-strong bg-surface-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:border-primary/40 hover:text-text-primary"
        >
          <RotateCw className="h-3.5 w-3.5" />
          Retry
        </button>
      )}
    </div>
  );
}
