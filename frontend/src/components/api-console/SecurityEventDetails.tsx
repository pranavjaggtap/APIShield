import type { ReactNode } from "react";
import { AlertTriangle, ShieldQuestion, X } from "lucide-react";
import type { SecurityEventRecord, SecurityEventThreatSignal } from "../../types/apiConsole";
import { useSecurityEvent } from "../../hooks/useSecurityEvents";
import { formatDateTime, formatRiskScore } from "../../lib/formatters";
import { cn } from "../../lib/cn";
import { Badge, type BadgeColor } from "../common/Badge";
import { RiskBadge } from "../security/RiskBadge";
import { THREAT_META, riskBadgeColor, threatTypeForDetector } from "../security/securityMeta";
import { EventDecisionBadge } from "./EventDecisionBadge";

interface SecurityEventDetailsProps {
  /** The row as listed - shown immediately while the full event is fetched by id. */
  summary: SecurityEventRecord;
  accessToken: string;
  onClose: () => void;
}

const BAR_COLOR: Record<BadgeColor, string> = {
  success: "bg-success",
  warning: "bg-warning",
  orange: "bg-orange",
  danger: "bg-danger",
  critical: "bg-critical",
  primary: "bg-primary",
  secondary: "bg-secondary",
  neutral: "bg-text-muted",
};

/** Detected signals first (strongest first), then clean ones - each group otherwise in API order. */
function orderSignals(signals: SecurityEventThreatSignal[]): SecurityEventThreatSignal[] {
  return [...signals].sort((a, b) => {
    if (a.detected !== b.detected) return a.detected ? -1 : 1;
    return a.detected ? b.severity - a.severity : 0;
  });
}

function Field({ label, children, mono = true }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-text-muted">{label}</dt>
      <dd className={cn("mt-0.5 break-all text-xs text-text-primary", mono && "font-mono")}>{children}</dd>
    </div>
  );
}

function SignalRow({ signal }: { signal: SecurityEventThreatSignal }) {
  const threatType = threatTypeForDetector(signal.detector);
  const meta = threatType ? THREAT_META[threatType] : null;
  const Icon = meta?.icon ?? ShieldQuestion;
  const severityPercent = Math.max(0, Math.min(1, signal.severity)) * 100;

  return (
    <li
      className={cn(
        "rounded-lg border p-3",
        signal.detected ? "border-danger/25 bg-danger/5" : "border-border bg-surface-raised",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <Icon className={cn("h-3.5 w-3.5 shrink-0", signal.detected ? "text-danger" : "text-text-muted")} strokeWidth={1.75} />
          <span className="truncate text-xs font-medium text-text-primary">{meta?.label ?? signal.detector}</span>
          {meta && <span className="truncate font-mono text-[10px] text-text-muted">{signal.detector}</span>}
        </div>
        <Badge color={signal.detected ? "danger" : "neutral"} className="shrink-0">
          {signal.detected ? "Detected" : "Clean"}
        </Badge>
      </div>

      <div className="mt-2 flex items-center gap-2">
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface" aria-hidden="true">
          <div
            className={cn("h-full rounded-full", signal.detected ? BAR_COLOR[riskBadgeColor(signal.severity)] : "bg-border-strong")}
            style={{ width: `${severityPercent}%` }}
          />
        </div>
        <span className="w-10 text-right font-mono text-[11px] text-text-secondary" aria-label="Severity">
          {formatRiskScore(signal.severity)}
        </span>
      </div>

      <p className="mt-1.5 break-words text-[11px] leading-snug text-text-secondary">{signal.description}</p>
    </li>
  );
}

export function SecurityEventDetails({ summary, accessToken, onClose }: SecurityEventDetailsProps) {
  const { event: fetched, error, loading } = useSecurityEvent(summary.id, accessToken);
  const event = fetched ?? summary;
  const signals = orderSignals(event.threatSignals);
  const detectedCount = signals.filter((signal) => signal.detected).length;

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-border bg-surface-raised/40 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Event details</p>
          <p className="mt-0.5 truncate font-mono text-xs text-text-secondary" title={event.id}>
            {event.id}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {loading && (
            <span className="h-3 w-3 animate-spin rounded-full border-2 border-border-strong border-t-primary" role="status" aria-label="Refreshing event" />
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close event details"
            className="flex h-7 w-7 items-center justify-center rounded-md text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-warning/25 bg-warning/5 px-3 py-2 text-[11px] text-warning">
          <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
          <span>
            {error.kind === "NOT_FOUND"
              ? "This event no longer exists on APIShield - showing the data from the list."
              : `Could not refresh this event: ${error.message} Showing the data from the list.`}
          </span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <EventDecisionBadge decision={event.decision} />
        <span className="text-xs text-text-secondary">{event.decisionReason}</span>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
        <Field label="Time">
          <time dateTime={event.timestamp} title={event.timestamp}>
            {formatDateTime(event.timestamp)}
          </time>
        </Field>
        <Field label="Request ID">{event.requestId}</Field>
        <Field label="Method">{event.method}</Field>
        <Field label="Client IP">{event.clientIp}</Field>
        <div className="col-span-2">
          <Field label="Path">{event.path}</Field>
        </div>
        <Field label="User">{event.userId ?? <span className="text-text-muted">Not authenticated</span>}</Field>
        <Field label="Route">{event.routeId ?? <span className="text-text-muted">None</span>}</Field>
        <Field label="Risk score" mono={false}>
          <RiskBadge riskScore={event.riskScore} />
        </Field>
        <Field label="Threat score" mono={false}>
          <RiskBadge riskScore={event.threatScore} />
        </Field>
      </dl>

      <div>
        <p className="mb-2 text-xs font-medium text-text-secondary">
          Threat signals{" "}
          <span className="text-text-muted">
            ({detectedCount} detected of {signals.length})
          </span>
        </p>
        {signals.length === 0 ? (
          <p className="text-[11px] text-text-muted">No detector produced a signal for this request.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {signals.map((signal, index) => (
              <SignalRow key={`${signal.detector}-${index}`} signal={signal} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
