import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TrafficPoint } from "../../types/dashboard";
import { formatNumber } from "../../lib/formatters";
import { ChartTooltip } from "./ChartTooltip";

interface TrafficChartProps {
  data: TrafficPoint[];
}

const hourTickFormatter = new Intl.DateTimeFormat("en-US", { hour: "2-digit", hour12: false });

const SERIES = [
  { key: "allowed" as const, label: "Allowed", color: "#10b981" },
  { key: "monitored" as const, label: "Monitored", color: "#f59e0b" },
  { key: "blocked" as const, label: "Blocked", color: "#ef4444" },
];

function TrafficTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { dataKey: string; value: number }[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0 || !label) return null;

  const rows = SERIES.map((series) => {
    const entry = payload.find((p) => p.dataKey === series.key);
    return { label: series.label, value: formatNumber(entry?.value ?? 0), color: series.color };
  });

  return <ChartTooltip title={hourTickFormatter.format(new Date(label))} rows={rows} />;
}

export function TrafficChart({ data }: TrafficChartProps) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
        <defs>
          {SERIES.map((series) => (
            <linearGradient key={series.key} id={`traffic-${series.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={series.color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={series.color} stopOpacity={0} />
            </linearGradient>
          ))}
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
          stroke="#667187"
          tick={{ fill: "#9aa5b8", fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          tickFormatter={(value: number) => formatNumber(value)}
          width={52}
        />
        <Tooltip content={<TrafficTooltip />} cursor={{ stroke: "#2a3242", strokeWidth: 1 }} />
        <Legend
          verticalAlign="top"
          height={28}
          align="right"
          iconType="circle"
          iconSize={8}
          formatter={(value: string) => <span className="text-xs text-text-secondary">{value}</span>}
        />
        {SERIES.map((series) => (
          <Area
            key={series.key}
            type="monotone"
            dataKey={series.key}
            name={series.label}
            stackId="traffic"
            stroke={series.color}
            strokeWidth={1.5}
            fill={`url(#traffic-${series.key})`}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
