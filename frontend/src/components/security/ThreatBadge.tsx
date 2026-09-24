import type { ThreatType } from "../../types/dashboard";
import { NO_THREAT_META, THREAT_META } from "./securityMeta";

interface ThreatBadgeProps {
  threatType: ThreatType | null;
}

/** Shows the threat type with its icon. Color-coding for threats lives in the
 * severity/decision badges next to it, not here - this keeps each badge's
 * meaning single-purpose and unambiguous. */
export function ThreatBadge({ threatType }: ThreatBadgeProps) {
  const meta = threatType ? THREAT_META[threatType] : NO_THREAT_META;
  const Icon = meta.icon;

  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-text-primary">
      <Icon className="h-3.5 w-3.5 text-text-secondary" strokeWidth={1.75} />
      {meta.label}
    </span>
  );
}
