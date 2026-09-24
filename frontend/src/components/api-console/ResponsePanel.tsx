import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, WifiOff } from "lucide-react";
import type { ApiResponseResult } from "../../types/apiConsole";
import { Badge, type BadgeColor } from "../common/Badge";
import { EmptyState } from "../common/EmptyState";
import { LoadingPanel } from "../common/LoadingState";
import { cn } from "../../lib/cn";

interface ResponsePanelProps {
  result: ApiResponseResult | null;
  loading: boolean;
  networkError: string | null;
}

function statusColor(status: number): BadgeColor {
  if (status >= 200 && status < 300) return "success";
  if (status === 403) return "danger";
  if (status >= 400 && status < 500) return "warning";
  if (status >= 500) return "critical";
  return "neutral";
}

/** Best-effort pretty-print; falls back to the raw text untouched if it isn't valid JSON. */
function formatBody(body: string): { formatted: string; isJson: boolean } {
  const trimmed = body.trim();
  if (!trimmed) return { formatted: "(empty response body)", isJson: false };
  try {
    return { formatted: JSON.stringify(JSON.parse(trimmed), null, 2), isJson: true };
  } catch {
    return { formatted: body, isJson: false };
  }
}

export function ResponsePanel({ result, loading, networkError }: ResponsePanelProps) {
  const [headersOpen, setHeadersOpen] = useState(false);
  const body = useMemo(() => (result ? formatBody(result.body) : null), [result]);

  if (loading) {
    return <LoadingPanel className="min-h-[280px]" />;
  }

  if (networkError) {
    return (
      <EmptyState
        icon={WifiOff}
        title="Network error"
        description={networkError}
        className="min-h-[280px]"
      />
    );
  }

  if (!result) {
    return (
      <EmptyState
        title="No response yet"
        description="Send a request to see the real response from APIShield here."
        className="min-h-[280px]"
      />
    );
  }

  const headerEntries = Object.entries(result.headers);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <Badge color={statusColor(result.status)} className="text-sm">
          {result.status} {result.statusText}
        </Badge>
        <span className="text-xs text-text-muted">{result.durationMs.toFixed(0)} ms</span>
        <span className="text-xs text-text-muted">{new Date(result.timestamp).toLocaleTimeString()}</span>
      </div>

      {headerEntries.length > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setHeadersOpen((open) => !open)}
            className="flex items-center gap-1.5 text-xs font-medium text-text-secondary transition-colors hover:text-text-primary"
          >
            {headersOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Response Headers ({headerEntries.length})
          </button>
          {headersOpen && (
            <div className="mt-2 flex flex-col gap-1 rounded-lg border border-border bg-surface-raised px-3 py-2.5">
              {headerEntries.map(([key, value]) => (
                <div key={key} className="flex gap-2 font-mono text-[11px]">
                  <span className="shrink-0 text-text-muted">{key}:</span>
                  <span className={cn("truncate text-text-secondary")}>{value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div>
        <p className="mb-1.5 text-xs font-medium text-text-secondary">Response Body</p>
        <pre className="max-h-[320px] overflow-auto rounded-lg border border-border bg-surface-raised px-3 py-2.5 font-mono text-[11px] leading-relaxed text-text-primary">
          {body?.formatted}
        </pre>
      </div>
    </div>
  );
}
