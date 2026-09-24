import type {
  DashboardSummary,
  DecisionStatistic,
  RiskPoint,
  SecurityEvent,
  SystemHealth,
  ThreatStatistic,
  TrafficPoint,
} from "../types/dashboard";
import {
  mockDashboardSummary,
  mockDecisionStatistics,
  mockRiskSeries,
  mockSecurityEvents,
  mockSystemHealth,
  mockThreatStatistics,
  mockTrafficSeries,
} from "../data/mockData";
import type { DashboardService } from "./dashboardService";

/** Simulates real network latency so loading states are genuinely exercised. */
function delay<T>(value: T, ms: number): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

/**
 * Default mock implementation - realistic latency, always succeeds, backed by
 * the fixtures in data/mockData.ts. This is what getDashboardService() returns
 * today.
 */
export const mockDashboardService: DashboardService = {
  getSummary(): Promise<DashboardSummary> {
    return delay(mockDashboardSummary, 450);
  },
  getThreats(): Promise<ThreatStatistic[]> {
    return delay(mockThreatStatistics, 500);
  },
  getEvents(): Promise<SecurityEvent[]> {
    return delay(mockSecurityEvents, 550);
  },
  getTraffic(): Promise<TrafficPoint[]> {
    return delay(mockTrafficSeries, 600);
  },
  getRisk(): Promise<RiskPoint[]> {
    return delay(mockRiskSeries, 500);
  },
  getHealth(): Promise<SystemHealth> {
    return delay(mockSystemHealth, 350);
  },
  getDecisions(): Promise<DecisionStatistic[]> {
    return delay(mockDecisionStatistics, 500);
  },
};

/**
 * Not wired into the app by default. Available for manually verifying the
 * dashboard's error state during development - temporarily point
 * getDashboardService() (in dashboardService.ts) at this instead.
 */
export const erroringMockDashboardService: DashboardService = {
  getSummary: () => Promise.reject(new Error("Failed to load dashboard summary")),
  getThreats: () => Promise.reject(new Error("Failed to load threat statistics")),
  getEvents: () => Promise.reject(new Error("Failed to load security events")),
  getTraffic: () => Promise.reject(new Error("Failed to load traffic data")),
  getRisk: () => Promise.reject(new Error("Failed to load risk trend")),
  getHealth: () => Promise.reject(new Error("Failed to load system health")),
  getDecisions: () => Promise.reject(new Error("Failed to load decision statistics")),
};

/**
 * Not wired into the app by default. Available for manually verifying the
 * dashboard's empty state during development - temporarily point
 * getDashboardService() at this instead.
 */
export const emptyMockDashboardService: DashboardService = {
  getSummary: () => delay(mockDashboardSummary, 300),
  getThreats: () => delay([], 300),
  getEvents: () => delay([], 300),
  getTraffic: () => delay([], 300),
  getRisk: () => delay([], 300),
  getHealth: () => delay(mockSystemHealth, 300),
  getDecisions: () => delay([], 300),
};
