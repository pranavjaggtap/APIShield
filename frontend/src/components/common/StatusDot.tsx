import { cn } from "../../lib/cn";

export type StatusTone = "operational" | "degraded" | "down";

const TONE_STYLES: Record<StatusTone, { dot: string; text: string; ring: string }> = {
  operational: { dot: "bg-success", text: "text-success", ring: "bg-success/40" },
  degraded: { dot: "bg-warning", text: "text-warning", ring: "bg-warning/40" },
  down: { dot: "bg-danger", text: "text-danger", ring: "bg-danger/40" },
};

interface StatusDotProps {
  tone: StatusTone;
  label: string;
  pulse?: boolean;
  className?: string;
}

/** A small labeled status indicator with a restrained pulse for "live" states. */
export function StatusDot({ tone, label, pulse = true, className }: StatusDotProps) {
  const styles = TONE_STYLES[tone];

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <span className="relative flex h-2 w-2">
        {pulse && (
          <span className={cn("absolute inline-flex h-full w-full animate-ping rounded-full opacity-60", styles.ring)} />
        )}
        <span className={cn("relative inline-flex h-2 w-2 rounded-full", styles.dot)} />
      </span>
      <span className={cn("text-xs font-medium", styles.text)}>{label}</span>
    </div>
  );
}
