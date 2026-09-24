import { Activity, Gauge, ShieldAlert, ShieldBan } from "lucide-react";
import type { DashboardSummary } from "../../types/dashboard";
import { formatNumber, formatRiskScore } from "../../lib/formatters";
import { KpiCard } from "./KpiCard";

interface KpiGridProps {
  summary: DashboardSummary;
}

export function KpiGrid({ summary }: KpiGridProps) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        icon={Activity}
        label="Total Requests"
        value={formatNumber(summary.totalRequests)}
        trend={summary.totalRequestsTrend}
        trendDirection="neutral"
        supportingText="API traffic processed through the gateway"
      />
      <KpiCard
        icon={ShieldAlert}
        label="Threats Detected"
        value={formatNumber(summary.threatsDetected)}
        trend={summary.threatsDetectedTrend}
        trendDirection={summary.threatsDetectedTrend <= 0 ? "positive" : "negative"}
        supportingText="Flagged by the security pipeline"
      />
      <KpiCard
        icon={ShieldBan}
        label="Requests Blocked"
        value={formatNumber(summary.requestsBlocked)}
        trend={summary.requestsBlockedTrend}
        trendDirection={summary.requestsBlockedTrend <= 0 ? "positive" : "negative"}
        supportingText="Denied by the decision engine"
      />
      <KpiCard
        icon={Gauge}
        label="Average Risk Score"
        value={formatRiskScore(summary.averageRiskScore)}
        trend={summary.averageRiskScoreTrend}
        trendDirection={summary.averageRiskScoreTrend <= 0 ? "positive" : "negative"}
        supportingText="Across all evaluated requests"
      />
    </div>
  );
}
