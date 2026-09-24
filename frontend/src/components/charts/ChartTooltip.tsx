import type { ReactNode } from "react";

interface TooltipRow {
  label: string;
  value: string;
  color: string;
}

interface ChartTooltipProps {
  title: string;
  rows: TooltipRow[];
}

/**
 * The dark-theme tooltip body every chart on the dashboard renders instead of
 * Recharts' default white tooltip. Charts pass their own formatted rows in -
 * this component only owns the visual shell.
 */
export function ChartTooltip({ title, rows }: ChartTooltipProps): ReactNode {
  return (
    <div className="min-w-[160px] rounded-lg border border-border-strong bg-surface-raised px-3 py-2.5 shadow-lg shadow-black/40">
      <p className="mb-1.5 text-xs font-medium text-text-secondary">{title}</p>
      <div className="flex flex-col gap-1">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between gap-4 text-xs">
            <span className="flex items-center gap-1.5 text-text-secondary">
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: row.color }} />
              {row.label}
            </span>
            <span className="font-semibold text-text-primary">{row.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
