import type { LucideIcon } from "lucide-react";
import { TrendingDown, TrendingUp } from "lucide-react";
import { cn } from "../../lib/cn";
import { formatTrend } from "../../lib/formatters";

export type TrendDirection = "positive" | "negative" | "neutral";

interface KpiCardProps {
  icon: LucideIcon;
  label: string;
  value: string;
  trend: number;
  trendDirection: TrendDirection;
  supportingText: string;
}

const TREND_STYLES: Record<TrendDirection, string> = {
  positive: "text-success",
  negative: "text-danger",
  neutral: "text-text-muted",
};

export function KpiCard({ icon: Icon, label, value, trend, trendDirection, supportingText }: KpiCardProps) {
  const TrendIcon = trend >= 0 ? TrendingUp : TrendingDown;

  return (
    <div className="group rounded-xl border border-border bg-surface p-5 transition-colors duration-200 hover:border-border-strong hover:bg-surface-hover">
      <div className="flex items-start justify-between">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface-raised text-primary transition-colors duration-200 group-hover:border-primary/30">
          <Icon className="h-[18px] w-[18px]" strokeWidth={1.75} />
        </span>
        <span className={cn("flex items-center gap-1 text-xs font-medium", TREND_STYLES[trendDirection])}>
          <TrendIcon className="h-3.5 w-3.5" strokeWidth={2} />
          {formatTrend(trend)}
        </span>
      </div>

      <p className="mt-4 text-2xl font-semibold tracking-tight text-text-primary">{value}</p>
      <p className="mt-1 text-sm text-text-secondary">{label}</p>
      <p className="mt-2.5 border-t border-border pt-2.5 text-xs text-text-muted">{supportingText}</p>
    </div>
  );
}
