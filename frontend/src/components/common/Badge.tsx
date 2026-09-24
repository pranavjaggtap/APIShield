import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export type BadgeColor =
  | "success"
  | "warning"
  | "orange"
  | "danger"
  | "critical"
  | "primary"
  | "secondary"
  | "neutral";

const COLOR_STYLES: Record<BadgeColor, string> = {
  success: "bg-success/10 text-success border-success/20",
  warning: "bg-warning/10 text-warning border-warning/20",
  orange: "bg-orange/10 text-orange border-orange/20",
  danger: "bg-danger/10 text-danger border-danger/20",
  critical: "bg-critical/15 text-critical border-critical/30",
  primary: "bg-primary/10 text-primary border-primary/20",
  secondary: "bg-secondary/10 text-secondary border-secondary/20",
  neutral: "bg-white/5 text-text-secondary border-border-strong",
};

interface BadgeProps {
  color: BadgeColor;
  children: ReactNode;
  icon?: ReactNode;
  className?: string;
}

/** The single badge primitive every threat/decision/severity badge is built from. */
export function Badge({ color, children, icon, className }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium",
        COLOR_STYLES[color],
        className,
      )}
    >
      {icon}
      {children}
    </span>
  );
}
