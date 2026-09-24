import { Database, Layers, Server, ShieldCheck } from "lucide-react";
import type { ComponentStatus, SystemHealth } from "../../types/dashboard";
import { StatusDot, type StatusTone } from "../common/StatusDot";

interface SystemHealthPanelProps {
  health: SystemHealth;
}

const STATUS_TONE: Record<ComponentStatus, StatusTone> = {
  OPERATIONAL: "operational",
  DEGRADED: "degraded",
  DOWN: "down",
};

const STATUS_LABEL: Record<ComponentStatus, string> = {
  OPERATIONAL: "Operational",
  DEGRADED: "Degraded",
  DOWN: "Down",
};

const COMPONENTS = [
  { key: "gateway" as const, label: "APIShield Gateway", icon: Server },
  { key: "redis" as const, label: "Redis", icon: Layers },
  { key: "postgresql" as const, label: "PostgreSQL", icon: Database },
  { key: "securityPipeline" as const, label: "Security Pipeline", icon: ShieldCheck },
];

export function SystemHealthPanel({ health }: SystemHealthPanelProps) {
  return (
    <div className="flex flex-col divide-y divide-border/60">
      {COMPONENTS.map(({ key, label, icon: Icon }) => {
        const status = health[key];
        return (
          <div key={key} className="flex items-center justify-between py-2.5 first:pt-0 last:pb-0">
            <div className="flex items-center gap-2.5">
              <Icon className="h-4 w-4 text-text-muted" strokeWidth={1.75} />
              <span className="text-sm text-text-secondary">{label}</span>
            </div>
            <StatusDot tone={STATUS_TONE[status]} label={STATUS_LABEL[status]} pulse={status === "OPERATIONAL"} />
          </div>
        );
      })}
    </div>
  );
}
