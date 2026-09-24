import { CheckCircle2, Eye, XCircle } from "lucide-react";
import type { DecisionOutcome } from "../../types/dashboard";
import { Badge } from "../common/Badge";
import { DECISION_META } from "./securityMeta";

const DECISION_ICON: Record<DecisionOutcome, typeof CheckCircle2> = {
  ALLOW: CheckCircle2,
  MONITOR: Eye,
  BLOCK: XCircle,
};

interface DecisionBadgeProps {
  decision: DecisionOutcome;
}

export function DecisionBadge({ decision }: DecisionBadgeProps) {
  const meta = DECISION_META[decision];
  const Icon = DECISION_ICON[decision];

  return (
    <Badge color={meta.color} icon={<Icon className="h-3 w-3" strokeWidth={2} />}>
      {meta.label}
    </Badge>
  );
}
