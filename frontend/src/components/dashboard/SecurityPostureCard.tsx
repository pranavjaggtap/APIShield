import { ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";
import type { DashboardSummary, SecurityPosture } from "../../types/dashboard";
import { formatRiskScore } from "../../lib/formatters";
import { cn } from "../../lib/cn";

interface SecurityPostureCardProps {
  summary: DashboardSummary;
}

const POSTURE_META: Record<
  SecurityPosture,
  { label: string; icon: typeof ShieldCheck; color: string; glow: string; badgeBg: string }
> = {
  PROTECTED: {
    label: "Protected",
    icon: ShieldCheck,
    color: "text-success",
    glow: "rgba(16,185,129,0.16)",
    badgeBg: "bg-success/10 border-success/25",
  },
  AT_RISK: {
    label: "At Risk",
    icon: ShieldAlert,
    color: "text-warning",
    glow: "rgba(245,158,11,0.16)",
    badgeBg: "bg-warning/10 border-warning/25",
  },
  CRITICAL: {
    label: "Critical",
    icon: ShieldX,
    color: "text-danger",
    glow: "rgba(239,68,68,0.16)",
    badgeBg: "bg-danger/10 border-danger/25",
  },
};

export function SecurityPostureCard({ summary }: SecurityPostureCardProps) {
  const meta = POSTURE_META[summary.securityPosture];
  const Icon = meta.icon;
  const riskPercent = Math.round(summary.averageRiskScore * 100);

  return (
    <div className="relative overflow-hidden rounded-xl border border-border bg-surface">
      {/* Restrained corner glow - a single soft radial gradient, not a neon wash */}
      <div
        className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full blur-3xl"
        style={{ backgroundColor: meta.glow }}
      />

      <div className="relative flex flex-col gap-8 p-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-start gap-4">
          <span
            className={cn(
              "flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border",
              meta.badgeBg,
            )}
          >
            <Icon className={cn("h-7 w-7", meta.color)} strokeWidth={1.75} />
          </span>
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-text-muted">Security Posture</p>
            <p className={cn("mt-1 text-2xl font-semibold tracking-tight", meta.color)}>
              {meta.label.toUpperCase()}
            </p>
            <p className="mt-2 max-w-md text-sm text-text-secondary">{summary.postureExplanation}</p>
          </div>
        </div>

        <div className="flex shrink-0 flex-col gap-2 lg:w-64">
          <div className="flex items-baseline justify-between">
            <p className="text-xs font-medium uppercase tracking-wider text-text-muted">Risk Score</p>
            <p className="text-xs text-text-muted">Block threshold 0.50</p>
          </div>
          <p className="text-3xl font-semibold tracking-tight text-text-primary">
            {formatRiskScore(summary.averageRiskScore)}
          </p>
          <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-surface-raised">
            <div
              className="absolute left-0 top-0 h-full rounded-full bg-gradient-to-r from-primary to-secondary transition-all duration-500"
              style={{ width: `${riskPercent}%` }}
            />
            <div className="absolute top-0 h-full w-px bg-danger/70" style={{ left: "50%" }} />
          </div>
        </div>
      </div>
    </div>
  );
}
