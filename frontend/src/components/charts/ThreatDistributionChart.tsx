import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { ThreatStatistic } from "../../types/dashboard";
import { formatNumber, formatPercentage } from "../../lib/formatters";
import { THREAT_META } from "../security/securityMeta";
import { ChartTooltip } from "./ChartTooltip";
import { EmptyState } from "../common/EmptyState";

interface ThreatDistributionChartProps {
  data: ThreatStatistic[];
}

function ThreatTooltip({ active, payload }: { active?: boolean; payload?: { payload: ThreatStatistic }[] }) {
  if (!active || !payload || payload.length === 0) return null;
  const stat = payload[0].payload;
  const meta = THREAT_META[stat.threatType];

  return (
    <ChartTooltip
      title={meta.label}
      rows={[
        { label: "Events", value: formatNumber(stat.count), color: meta.chartColor },
        { label: "Share", value: formatPercentage(stat.percentage), color: meta.chartColor },
      ]}
    />
  );
}

export function ThreatDistributionChart({ data }: ThreatDistributionChartProps) {
  if (data.length === 0) {
    return <EmptyState title="No threats recorded" description="No threat signals in the selected time range." />;
  }

  const sorted = [...data].sort((a, b) => b.count - a.count);

  return (
    <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
      <div className="mx-auto w-full max-w-[190px] shrink-0">
        <ResponsiveContainer width="100%" height={190}>
          <PieChart>
            <Pie
              data={sorted}
              dataKey="count"
              nameKey="threatType"
              innerRadius={58}
              outerRadius={82}
              paddingAngle={2}
              stroke="#090c12"
              strokeWidth={2}
            >
              {sorted.map((entry) => (
                <Cell key={entry.threatType} fill={THREAT_META[entry.threatType].chartColor} />
              ))}
            </Pie>
            <Tooltip content={<ThreatTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="flex-1 space-y-2.5">
        {sorted.map((stat) => {
          const meta = THREAT_META[stat.threatType];
          const Icon = meta.icon;
          return (
            <div key={stat.threatType} className="flex items-center gap-3">
              <span
                className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md"
                style={{ backgroundColor: `${meta.chartColor}1a` }}
              >
                <Icon className="h-3.5 w-3.5" style={{ color: meta.chartColor }} strokeWidth={1.75} />
              </span>
              <span className="min-w-0 flex-1 truncate text-xs font-medium text-text-primary">{meta.label}</span>
              <span className="text-xs text-text-muted">{formatNumber(stat.count)}</span>
              <span className="w-11 text-right text-xs font-semibold text-text-secondary">
                {formatPercentage(stat.percentage)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
