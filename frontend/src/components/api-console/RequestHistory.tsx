import { History } from "lucide-react";
import type { RequestHistoryEntry, SecurityInference } from "../../types/apiConsole";
import { formatTime } from "../../lib/formatters";
import { Badge, type BadgeColor } from "../common/Badge";
import { EmptyState } from "../common/EmptyState";

interface RequestHistoryProps {
  entries: RequestHistoryEntry[];
}

const INFERENCE_COLOR: Record<SecurityInference, BadgeColor> = {
  BLOCKED: "danger",
  NOT_BLOCKED: "success",
  UNKNOWN: "neutral",
};

const METHOD_COLOR: Record<string, string> = {
  GET: "text-success",
  POST: "text-warning",
  PUT: "text-primary",
  DELETE: "text-danger",
};

/**
 * Current-session only, held in React state by the parent page - not
 * persisted anywhere. Cleared on page refresh, deliberately (no PostgreSQL
 * persistence in this block).
 */
export function RequestHistory({ entries }: RequestHistoryProps) {
  if (entries.length === 0) {
    return (
      <EmptyState
        icon={History}
        title="No requests sent yet"
        description="Requests you send in this session will appear here."
      />
    );
  }

  return (
    <div className="flex max-h-[420px] flex-col gap-1 overflow-y-auto">
      {entries.map((entry) => (
        <div
          key={entry.id}
          className="flex items-center gap-3 rounded-lg border border-transparent px-2 py-2 text-xs transition-colors hover:border-border hover:bg-surface-hover"
        >
          <span className="w-16 shrink-0 font-mono text-text-muted">{formatTime(entry.timestamp)}</span>
          <span className={`w-14 shrink-0 font-mono font-semibold ${METHOD_COLOR[entry.method] ?? "text-text-secondary"}`}>
            {entry.method}
          </span>
          <span className="min-w-0 flex-1 truncate font-mono text-text-primary">{entry.path}</span>
          <span className="w-10 shrink-0 text-right font-mono text-text-secondary">{entry.status ?? "—"}</span>
          <span className="w-9 shrink-0 text-right text-text-muted">{entry.durationMs.toFixed(0)}ms</span>
          <Badge color={INFERENCE_COLOR[entry.securityInference]} className="w-[92px] shrink-0 justify-center">
            {entry.securityInference.replace("_", " ")}
          </Badge>
        </div>
      ))}
    </div>
  );
}
