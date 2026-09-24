import type { SecurityEvent } from "../../types/dashboard";
import { formatTime } from "../../lib/formatters";
import { cn } from "../../lib/cn";
import { EmptyState } from "../common/EmptyState";
import { DECISION_META, NO_THREAT_META, THREAT_META } from "../security/securityMeta";

interface LiveActivityFeedProps {
  events: SecurityEvent[];
}

function describeEvent(event: SecurityEvent): string {
  if (!event.threatType) {
    return "Request evaluated - no threat detected";
  }
  const label = THREAT_META[event.threatType].label;
  return `${label} detected`;
}

export function LiveActivityFeed({ events }: LiveActivityFeedProps) {
  if (events.length === 0) {
    return <EmptyState title="No recent activity" description="Live security events will stream in here." />;
  }

  return (
    <div className="flex flex-col">
      {events.map((event, index) => {
        const meta = event.threatType ? THREAT_META[event.threatType] : NO_THREAT_META;
        const decisionMeta = DECISION_META[event.decision];
        const Icon = meta.icon;

        return (
          <div
            key={event.id}
            className={cn(
              "flex items-start gap-3 py-3",
              index !== events.length - 1 && "border-b border-border/60",
            )}
          >
            <span
              className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
              style={{ backgroundColor: `${meta.chartColor}1a` }}
            >
              <Icon className="h-3.5 w-3.5" style={{ color: meta.chartColor }} strokeWidth={1.75} />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <p className="truncate text-sm font-medium text-text-primary">{describeEvent(event)}</p>
                <span className="shrink-0 font-mono text-[11px] text-text-muted">{formatTime(event.timestamp)}</span>
              </div>
              <p className="mt-0.5 truncate font-mono text-xs text-text-muted">{event.endpoint}</p>
              <p className="mt-1 text-xs font-medium" style={{ color: decisionMeta.chartColor }}>
                Request {event.decision === "ALLOW" ? "allowed" : event.decision === "MONITOR" ? "flagged for monitoring" : "blocked"}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
