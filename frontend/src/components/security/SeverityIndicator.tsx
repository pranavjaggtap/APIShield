import type { Severity } from "../../types/dashboard";
import { cn } from "../../lib/cn";
import { SEVERITY_META } from "./securityMeta";

interface SeverityIndicatorProps {
  severity: Severity;
  className?: string;
}

/** A compact dot + label used where a full Badge would be too heavy (e.g. dense feeds). */
export function SeverityIndicator({ severity, className }: SeverityIndicatorProps) {
  const meta = SEVERITY_META[severity];

  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium text-text-secondary", className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", meta.dotClassName)} />
      {meta.label}
    </span>
  );
}
