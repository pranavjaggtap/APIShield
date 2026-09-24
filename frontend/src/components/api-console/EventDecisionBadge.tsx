import { Badge } from "../common/Badge";
import { DecisionBadge } from "../security/DecisionBadge";
import { isKnownDecision } from "../security/securityMeta";

interface EventDecisionBadgeProps {
  decision: string;
}

/**
 * Persisted decisions arrive as plain strings. Known outcomes reuse the dashboard's DecisionBadge;
 * anything else (e.g. an outcome added to the backend later) still renders, neutrally, instead of breaking.
 */
export function EventDecisionBadge({ decision }: EventDecisionBadgeProps) {
  if (isKnownDecision(decision)) {
    return <DecisionBadge decision={decision} />;
  }
  return <Badge color="neutral">{decision}</Badge>;
}
