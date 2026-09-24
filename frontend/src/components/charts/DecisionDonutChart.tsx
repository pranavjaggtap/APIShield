import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { DecisionStatistic } from "../../types/dashboard";
import { formatNumber, formatPercentage } from "../../lib/formatters";
import { DECISION_META } from "../security/securityMeta";
import { ChartTooltip } from "./ChartTooltip";

interface DecisionDonutChartProps {
  data: DecisionStatistic[];
}

function DecisionTooltip({ active, payload }: { active?: boolean; payload?: { payload: DecisionStatistic }[] }) {
  if (!active || !payload || payload.length === 0) return null;
  const stat = payload[0].payload;
  const meta = DECISION_META[stat.decision];

  return (
    <ChartTooltip
      title={meta.label}
      rows={[
        { label: "Requests", value: formatNumber(stat.count), color: meta.chartColor },
        { label: "Share", value: formatPercentage(stat.percentage), color: meta.chartColor },
      ]}
    />
  );
}

export function DecisionDonutChart({ data }: DecisionDonutChartProps) {
  return (
    <ResponsiveContainer width="100%" height={180}>
      <PieChart>
        <Pie
          data={data}
          dataKey="count"
          nameKey="decision"
          innerRadius={54}
          outerRadius={78}
          paddingAngle={2}
          stroke="#090c12"
          strokeWidth={2}
        >
          {data.map((entry) => (
            <Cell key={entry.decision} fill={DECISION_META[entry.decision].chartColor} />
          ))}
        </Pie>
        <Tooltip content={<DecisionTooltip />} />
      </PieChart>
    </ResponsiveContainer>
  );
}
