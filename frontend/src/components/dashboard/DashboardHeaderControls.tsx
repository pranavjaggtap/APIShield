import { useState } from "react";
import { RotateCw } from "lucide-react";
import type { ComponentStatus, SystemHealth } from "../../types/dashboard";
import { StatusDot, type StatusTone } from "../common/StatusDot";
import { cn } from "../../lib/cn";

interface DashboardHeaderControlsProps {
  health: SystemHealth;
  loading: boolean;
  onRefresh: () => void;
}

const STATUS_TONE: Record<ComponentStatus, StatusTone> = {
  OPERATIONAL: "operational",
  DEGRADED: "degraded",
  DOWN: "down",
};

const TIME_RANGES = ["Last hour", "Last 24 hours", "Last 7 days"] as const;

export function DashboardHeaderControls({ health, loading, onRefresh }: DashboardHeaderControlsProps) {
  const [timeRange, setTimeRange] = useState<(typeof TIME_RANGES)[number]>("Last 24 hours");

  return (
    <>
      <div className="flex items-center gap-4 rounded-lg border border-border bg-surface px-3 py-2">
        <StatusDot tone={STATUS_TONE[health.gateway]} label="Gateway" pulse={health.gateway === "OPERATIONAL"} />
        <span className="h-3 w-px bg-border" aria-hidden="true" />
        <StatusDot tone={STATUS_TONE[health.redis]} label="Redis" pulse={health.redis === "OPERATIONAL"} />
        <span className="h-3 w-px bg-border" aria-hidden="true" />
        <StatusDot
          tone={STATUS_TONE[health.postgresql]}
          label="PostgreSQL"
          pulse={health.postgresql === "OPERATIONAL"}
        />
      </div>

      <label className="sr-only" htmlFor="dashboard-time-range">
        Time range
      </label>
      <select
        id="dashboard-time-range"
        value={timeRange}
        onChange={(event) => setTimeRange(event.target.value as (typeof TIME_RANGES)[number])}
        className="rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-text-secondary outline-none transition-colors hover:border-border-strong focus:border-primary/50"
      >
        {TIME_RANGES.map((range) => (
          <option key={range} value={range}>
            {range}
          </option>
        ))}
      </select>

      <button
        type="button"
        onClick={onRefresh}
        disabled={loading}
        aria-label="Refresh dashboard data"
        className="flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-text-secondary transition-colors hover:border-border-strong hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-60"
      >
        <RotateCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
        Refresh
      </button>
    </>
  );
}
