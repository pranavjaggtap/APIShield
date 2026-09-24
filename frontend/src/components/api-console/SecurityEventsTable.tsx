import type { KeyboardEvent } from "react";
import type { SecurityEventRecord } from "../../types/apiConsole";
import { formatDateTime } from "../../lib/formatters";
import { cn } from "../../lib/cn";
import { RiskBadge } from "../security/RiskBadge";
import { EventDecisionBadge } from "./EventDecisionBadge";

interface SecurityEventsTableProps {
  events: SecurityEventRecord[];
  selectedId: string | null;
  onSelect: (event: SecurityEventRecord) => void;
}

const COLUMNS = ["Time", "Request ID", "Method", "Path", "Client IP", "User", "Decision", "Risk Score", "Threat Score"];

/** Rows are selectable (click, Enter or Space) to open the event's details. */
export function SecurityEventsTable({ events, selectedId, onSelect }: SecurityEventsTableProps) {
  function handleKeyDown(event: KeyboardEvent<HTMLTableRowElement>, record: SecurityEventRecord) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(record);
    }
  }

  return (
    <div className="max-h-[520px] overflow-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-10 bg-surface-raised">
          <tr>
            {COLUMNS.map((column) => (
              <th
                key={column}
                scope="col"
                className="whitespace-nowrap border-b border-border px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-text-muted"
              >
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((record) => {
            const isSelected = record.id === selectedId;
            return (
              <tr
                key={record.id}
                tabIndex={0}
                aria-selected={isSelected}
                onClick={() => onSelect(record)}
                onKeyDown={(event) => handleKeyDown(event, record)}
                className={cn(
                  "cursor-pointer border-b border-border/60 outline-none transition-colors duration-150 last:border-b-0 focus-visible:bg-surface-hover",
                  isSelected ? "bg-primary/10 hover:bg-primary/15" : "hover:bg-surface-hover",
                )}
              >
                <td className="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-text-secondary">
                  <time dateTime={record.timestamp} title={record.timestamp}>
                    {formatDateTime(record.timestamp)}
                  </time>
                </td>
                <td className="max-w-[120px] truncate whitespace-nowrap px-3 py-2.5 font-mono text-xs text-text-muted" title={record.requestId}>
                  {record.requestId}
                </td>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <span className="rounded border border-border-strong bg-surface-raised px-1.5 py-0.5 font-mono text-[11px] font-medium text-text-secondary">
                    {record.method}
                  </span>
                </td>
                <td className="max-w-[180px] truncate whitespace-nowrap px-3 py-2.5 font-mono text-xs text-text-primary" title={record.path}>
                  {record.path}
                </td>
                <td className="max-w-[140px] truncate whitespace-nowrap px-3 py-2.5 font-mono text-xs text-text-secondary" title={record.clientIp}>
                  {record.clientIp}
                </td>
                <td className="max-w-[140px] truncate whitespace-nowrap px-3 py-2.5 font-mono text-xs" title={record.userId ?? undefined}>
                  {record.userId ? (
                    <span className="text-text-primary">{record.userId}</span>
                  ) : (
                    <span className="text-text-muted">—</span>
                  )}
                </td>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <EventDecisionBadge decision={record.decision} />
                </td>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <RiskBadge riskScore={record.riskScore} />
                </td>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <RiskBadge riskScore={record.threatScore} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
