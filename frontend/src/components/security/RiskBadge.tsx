import { formatRiskScore } from "../../lib/formatters";
import { Badge } from "../common/Badge";
import { riskBadgeColor } from "./securityMeta";

interface RiskBadgeProps {
  riskScore: number;
}

export function RiskBadge({ riskScore }: RiskBadgeProps) {
  return <Badge color={riskBadgeColor(riskScore)}>{formatRiskScore(riskScore)}</Badge>;
}
