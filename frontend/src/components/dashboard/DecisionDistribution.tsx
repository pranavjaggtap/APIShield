import type { DecisionStatistic } from "../../types/dashboard";
import { formatNumber, formatPercentage } from "../../lib/formatters";
import { cn } from "../../lib/cn";
import { EmptyState } from "../common/EmptyState";
import { DecisionDonutChart } from "../charts/DecisionDonutChart";
import { DECISION_META } from "../security/securityMeta";

interface DecisionDistributionProps {
  data: DecisionStatistic[];
}

export function DecisionDistribution({ data }: DecisionDistributionProps) {
  if (data.length === 0) {
    return <EmptyState title="No decisions recorded" description="Decision outcomes will appear here." />;
  }

  return (
    <div className="flex flex-col items-center gap-4">
      <DecisionDonutChart data={data} />
      <div className="grid w-full grid-cols-3 gap-2">
        {data.map((stat) => {
          const meta = DECISION_META[stat.decision];
          return (
            <div
              key={stat.decision}
              className="flex flex-col items-center gap-1 rounded-lg border border-border bg-surface-raised px-2 py-3 text-center"
            >
              <span
                className={cn("h-2 w-2 rounded-full")}
                style={{ backgroundColor: meta.chartColor }}
              />
              <span className="text-sm font-semibold text-text-primary">{formatNumber(stat.count)}</span>
              <span className="text-[11px] font-medium text-text-muted">{meta.label}</span>
              <span className="text-[11px] text-text-muted">{formatPercentage(stat.percentage)}</span>
            </div>
          );
        })}
      </div>
      {data.some((stat) => stat.decision === "MONITOR") && (
        <p className="text-center text-[11px] leading-relaxed text-text-muted">
          MONITOR is a planned decision state for a future risk-scoring tier. The current DecisionEngine
          supports ALLOW and BLOCK only.
        </p>
      )}
    </div>
  );
}
