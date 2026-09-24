/**
 * Core data model for the APIShield dashboard. These types are the contract the
 * mock service implements today and the future real backend service will need to
 * satisfy - see services/dashboardService.ts.
 */

export type ThreatType =
  | "SQL_INJECTION"
  | "XSS"
  | "REPLAY_ATTACK"
  | "FREQUENCY_ABUSE"
  | "BOT_AUTOMATION";

/**
 * MONITOR is anticipated future capability only. The current backend
 * DecisionEngine (com.apishield.decision.DefaultDecisionEngine) supports only
 * ALLOW and BLOCK - it has no intermediate "monitor and allow" outcome yet.
 * It is included here so the dashboard can visualize the intended three-state
 * decision model without claiming the backend already implements it.
 */
export type DecisionOutcome = "ALLOW" | "MONITOR" | "BLOCK";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ComponentStatus = "OPERATIONAL" | "DEGRADED" | "DOWN";

export type SecurityPosture = "PROTECTED" | "AT_RISK" | "CRITICAL";

export interface DashboardSummary {
  totalRequests: number;
  totalRequestsTrend: number;
  threatsDetected: number;
  threatsDetectedTrend: number;
  requestsBlocked: number;
  requestsBlockedTrend: number;
  averageRiskScore: number;
  averageRiskScoreTrend: number;
  securityPosture: SecurityPosture;
  postureExplanation: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  clientIp: string;
  method: string;
  endpoint: string;
  threatType: ThreatType | null;
  severity: Severity;
  riskScore: number;
  decision: DecisionOutcome;
}

export interface ThreatStatistic {
  threatType: ThreatType;
  count: number;
  percentage: number;
}

export interface TrafficPoint {
  timestamp: string;
  allowed: number;
  monitored: number;
  blocked: number;
}

export interface RiskPoint {
  timestamp: string;
  averageRiskScore: number;
}

export interface DecisionStatistic {
  decision: DecisionOutcome;
  count: number;
  percentage: number;
}

export interface SystemHealth {
  gateway: ComponentStatus;
  redis: ComponentStatus;
  postgresql: ComponentStatus;
  securityPipeline: ComponentStatus;
}
