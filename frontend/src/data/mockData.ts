import type {
  DashboardSummary,
  DecisionOutcome,
  DecisionStatistic,
  RiskPoint,
  SecurityEvent,
  Severity,
  SystemHealth,
  ThreatStatistic,
  ThreatType,
  TrafficPoint,
} from "../types/dashboard";

/**
 * MOCK / DEMO DATA ONLY.
 *
 * Every value in this file is a hand-authored or deterministically generated
 * fixture standing in for a future backend response. None of it originates from
 * real gateway traffic, real Redis counters, or real PostgreSQL-persisted
 * security events - that persistence layer does not exist yet. This file exists
 * so mockDashboardService.ts has something realistic-looking to serve while the
 * dashboard UI is built against a stable contract; see services/dashboardService.ts
 * for the interface a future ApiDashboardService would implement instead.
 */

export const mockDashboardSummary: DashboardSummary = {
  totalRequests: 128432,
  totalRequestsTrend: 8.2,
  threatsDetected: 342,
  threatsDetectedTrend: -4.1,
  requestsBlocked: 289,
  requestsBlockedTrend: -6.3,
  averageRiskScore: 0.32,
  averageRiskScoreTrend: -2.4,
  securityPosture: "PROTECTED",
  postureExplanation: "Gateway is actively monitoring incoming API traffic. All security detectors are operational.",
};

export const mockThreatStatistics: ThreatStatistic[] = [
  { threatType: "SQL_INJECTION", count: 118, percentage: 34.5 },
  { threatType: "BOT_AUTOMATION", count: 87, percentage: 25.4 },
  { threatType: "FREQUENCY_ABUSE", count: 64, percentage: 18.7 },
  { threatType: "XSS", count: 46, percentage: 13.5 },
  { threatType: "REPLAY_ATTACK", count: 27, percentage: 7.9 },
];

export const mockDecisionStatistics: DecisionStatistic[] = [
  { decision: "ALLOW", count: 127801, percentage: 94.6 },
  { decision: "MONITOR", count: 4342, percentage: 3.2 },
  { decision: "BLOCK", count: 289, percentage: 2.2 },
];

export const mockSystemHealth: SystemHealth = {
  gateway: "OPERATIONAL",
  redis: "OPERATIONAL",
  postgresql: "OPERATIONAL",
  securityPipeline: "OPERATIONAL",
};

// --- Deterministic time-series generation -----------------------------------
// A fixed sine-based generator so the traffic/risk charts look organic across
// a 24-hour window without relying on Math.random() (which would make the
// "demo data" change on every reload - undesirable for a fixture).

function hoursAgoIso(hoursAgo: number): string {
  const date = new Date();
  date.setMinutes(0, 0, 0);
  date.setHours(date.getHours() - hoursAgo);
  return date.toISOString();
}

export const mockTrafficSeries: TrafficPoint[] = Array.from({ length: 24 }, (_, i) => {
  const hoursAgo = 23 - i;
  const wave = Math.sin(i / 3) * 0.5 + 0.5; // 0..1
  const baseVolume = Math.round(4200 + wave * 3400);
  const blocked = Math.round(6 + wave * 14 + (i % 5 === 0 ? 10 : 0));
  const monitored = Math.round(40 + wave * 60);
  return {
    timestamp: hoursAgoIso(hoursAgo),
    allowed: baseVolume - blocked - monitored,
    monitored,
    blocked,
  };
});

export const mockRiskSeries: RiskPoint[] = Array.from({ length: 24 }, (_, i) => {
  const hoursAgo = 23 - i;
  const wave = Math.sin(i / 2.5 + 1) * 0.14 + 0.28;
  const spike = i === 15 ? 0.22 : 0; // one visible spike for a realistic story
  return {
    timestamp: hoursAgoIso(hoursAgo),
    averageRiskScore: Math.max(0.05, Math.min(0.95, wave + spike)),
  };
});

// --- Security events ----------------------------------------------------------

interface EventTemplate {
  minutesAgo: number;
  clientIp: string;
  method: string;
  endpoint: string;
  threatType: ThreatType | null;
  severity: Severity;
  riskScore: number;
  decision: DecisionOutcome;
}

const eventTemplates: EventTemplate[] = [
  { minutesAgo: 1, clientIp: "203.0.113.42", method: "GET", endpoint: "/api/users/1", threatType: "SQL_INJECTION", severity: "CRITICAL", riskScore: 0.95, decision: "BLOCK" },
  { minutesAgo: 3, clientIp: "198.51.100.17", method: "POST", endpoint: "/api/orders", threatType: "REPLAY_ATTACK", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
  { minutesAgo: 6, clientIp: "192.0.2.88", method: "GET", endpoint: "/api/users/5", threatType: "BOT_AUTOMATION", severity: "LOW", riskScore: 0.2, decision: "ALLOW" },
  { minutesAgo: 8, clientIp: "203.0.113.19", method: "GET", endpoint: "/api/search", threatType: "XSS", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
  { minutesAgo: 11, clientIp: "198.51.100.203", method: "GET", endpoint: "/api/users/12", threatType: "FREQUENCY_ABUSE", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
  { minutesAgo: 14, clientIp: "192.0.2.55", method: "GET", endpoint: "/api/users/3", threatType: null, severity: "LOW", riskScore: 0.04, decision: "ALLOW" },
  { minutesAgo: 17, clientIp: "203.0.113.77", method: "POST", endpoint: "/api/orders", threatType: "BOT_AUTOMATION", severity: "MEDIUM", riskScore: 0.4, decision: "MONITOR" },
  { minutesAgo: 21, clientIp: "198.51.100.64", method: "GET", endpoint: "/api/users/9", threatType: "SQL_INJECTION", severity: "CRITICAL", riskScore: 0.98, decision: "BLOCK" },
  { minutesAgo: 25, clientIp: "192.0.2.140", method: "GET", endpoint: "/api/products", threatType: null, severity: "LOW", riskScore: 0.03, decision: "ALLOW" },
  { minutesAgo: 29, clientIp: "203.0.113.201", method: "GET", endpoint: "/api/users/1", threatType: "REPLAY_ATTACK", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
  { minutesAgo: 34, clientIp: "198.51.100.9", method: "GET", endpoint: "/api/search", threatType: "XSS", severity: "MEDIUM", riskScore: 0.45, decision: "MONITOR" },
  { minutesAgo: 39, clientIp: "192.0.2.201", method: "GET", endpoint: "/api/users/21", threatType: "FREQUENCY_ABUSE", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
  { minutesAgo: 44, clientIp: "203.0.113.5", method: "GET", endpoint: "/api/users/7", threatType: null, severity: "LOW", riskScore: 0.06, decision: "ALLOW" },
  { minutesAgo: 51, clientIp: "198.51.100.150", method: "GET", endpoint: "/api/users/2", threatType: "BOT_AUTOMATION", severity: "MEDIUM", riskScore: 0.5, decision: "MONITOR" },
  { minutesAgo: 58, clientIp: "192.0.2.33", method: "POST", endpoint: "/api/orders", threatType: "SQL_INJECTION", severity: "CRITICAL", riskScore: 0.97, decision: "BLOCK" },
  { minutesAgo: 63, clientIp: "203.0.113.150", method: "GET", endpoint: "/api/users/18", threatType: null, severity: "LOW", riskScore: 0.02, decision: "ALLOW" },
  { minutesAgo: 70, clientIp: "198.51.100.44", method: "GET", endpoint: "/api/search", threatType: "XSS", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
  { minutesAgo: 78, clientIp: "192.0.2.9", method: "GET", endpoint: "/api/users/4", threatType: "REPLAY_ATTACK", severity: "HIGH", riskScore: 0.9, decision: "BLOCK" },
];

function minutesAgoIso(minutesAgo: number): string {
  return new Date(Date.now() - minutesAgo * 60_000).toISOString();
}

export const mockSecurityEvents: SecurityEvent[] = eventTemplates.map((template, index) => ({
  id: `evt-${index + 1}`,
  timestamp: minutesAgoIso(template.minutesAgo),
  clientIp: template.clientIp,
  method: template.method,
  endpoint: template.endpoint,
  threatType: template.threatType,
  severity: template.severity,
  riskScore: template.riskScore,
  decision: template.decision,
}));

// A short, more recent slice for the live activity feed - same shape as
// mockSecurityEvents, just the most recent few, mirroring what a real-time
// feed would show.
export const mockLiveActivity: SecurityEvent[] = mockSecurityEvents.slice(0, 6);
