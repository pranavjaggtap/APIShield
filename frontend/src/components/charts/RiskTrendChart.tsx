import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { RiskPoint } from "../../types/dashboard";
import { formatRiskScore } from "../../lib/formatters";
import { ChartTooltip } from "./ChartTooltip";

interface RiskTrendChartProps {
  data: RiskPoint[];
}

const hourTickFormatter = new Intl.DateTimeFormat("en-US", { hour: "2-digit", hour12: false });

const BLOCK_THRESHOLD = 0.5;

function RiskTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { value: number }[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0 || !label) return null;

  return (
    <ChartTooltip
      title={hourTickFormatter.format(new Date(label))}
      rows={[{ label: "Avg risk score", value: formatRiskScore(payload[0].value), color: "#3b82f6" }]}
    />
  );
}

export function RiskTrendChart({ data }: RiskTrendChartProps) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
        <defs>
          <linearGradient id="risk-line" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.25} />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e2531" strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="timestamp"
          tickFormatter={(value: string) => hourTickFormatter.format(new Date(value))}
          stroke="#667187"
          tick={{ fill: "#9aa5b8", fontSize: 11 }}
          tickLine={false}
          axisLine={{ stroke: "#1e2531" }}
          minTickGap={24}
        />
        <YAxis
          domain={[0, 1]}
          stroke="#667187"
          tick={{ fill: "#9aa5b8", fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          width={36}
        />
        <Tooltip content={<RiskTooltip />} cursor={{ stroke: "#2a3242", strokeWidth: 1 }} />
        <ReferenceLine
          y={BLOCK_THRESHOLD}
          stroke="#ef4444"
          strokeDasharray="4 4"
          strokeOpacity={0.6}
          label={{
            value: "Block threshold (0.5)",
            position: "insideTopRight",
            fill: "#ef4444",
            fontSize: 11,
          }}
        />
        <Line
          type="monotone"
          dataKey="averageRiskScore"
          stroke="#3b82f6"
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, fill: "#3b82f6", stroke: "#090c12", strokeWidth: 2 }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
