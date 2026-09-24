import type { SecurityEvent } from "../../types/dashboard";
import { formatTime } from "../../lib/formatters";
import { EmptyState } from "../common/EmptyState";
import { DecisionBadge } from "../security/DecisionBadge";
import { RiskBadge } from "../security/RiskBadge";
import { SeverityIndicator } from "../security/SeverityIndicator";
import { ThreatBadge } from "../security/ThreatBadge";

interface RecentEventsTableProps {
  events: SecurityEvent[];
}

const COLUMNS = ["Time", "Client / IP", "Method", "Endpoint", "Threat", "Severity", "Risk", "Decision"];

export function RecentEventsTable({ events }: RecentEventsTableProps) {
  if (events.length === 0) {
    return (
      <EmptyState
        title="No security events yet"
        description="Events will appear here as APIShield evaluates incoming traffic."
      />
    );
  }

  return (
    <div className="max-h-[440px] overflow-y-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-10 bg-surface-raised">
          <tr>
            {COLUMNS.map((column) => (
              <th
                key={column}
                scope="col"
                className="whitespace-nowrap border-b border-border px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-text-muted"
              >
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.id}
              className="border-b border-border/60 transition-colors duration-150 last:border-b-0 hover:bg-surface-hover"
            >
              <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-text-secondary">
                {formatTime(event.timestamp)}
              </td>
              <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-text-primary">{event.clientIp}</td>
              <td className="whitespace-nowrap px-4 py-2.5">
                <span className="rounded border border-border-strong bg-surface-raised px-1.5 py-0.5 font-mono text-[11px] font-medium text-text-secondary">
                  {event.method}
                </span>
              </td>
              <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-text-secondary">
                {event.endpoint}
              </td>
              <td className="whitespace-nowrap px-4 py-2.5">
                <ThreatBadge threatType={event.threatType} />
              </td>
              <td className="whitespace-nowrap px-4 py-2.5">
                <SeverityIndicator severity={event.severity} />
              </td>
              <td className="whitespace-nowrap px-4 py-2.5">
                <RiskBadge riskScore={event.riskScore} />
              </td>
              <td className="whitespace-nowrap px-4 py-2.5">
                <DecisionBadge decision={event.decision} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
