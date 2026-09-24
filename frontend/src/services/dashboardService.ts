import type {
  DashboardSummary,
  DecisionStatistic,
  RiskPoint,
  SecurityEvent,
  SystemHealth,
  ThreatStatistic,
  TrafficPoint,
} from "../types/dashboard";
import { mockDashboardService } from "./mockDashboardService";

/**
 * The contract every dashboard data source must satisfy. Today only
 * mockDashboardService implements this. When the backend exposes real
 * endpoints (see the method-level docs below for the planned routes), a new
 * apiDashboardService.ts implementing the same interface via fetch is the
 * only new file needed - getDashboardService() below is the single place
 * that changes, and no UI component needs to be touched.
 */
export interface DashboardService {
  /** Planned backend route: GET /api/dashboard/summary */
  getSummary(): Promise<DashboardSummary>;
  /** Planned backend route: GET /api/dashboard/threats */
  getThreats(): Promise<ThreatStatistic[]>;
  /** Planned backend route: GET /api/dashboard/events */
  getEvents(): Promise<SecurityEvent[]>;
  /** Planned backend route: GET /api/dashboard/traffic */
  getTraffic(): Promise<TrafficPoint[]>;
  /** Planned backend route: GET /api/dashboard/risk */
  getRisk(): Promise<RiskPoint[]>;
  /** Planned backend route: GET /api/dashboard/health */
  getHealth(): Promise<SystemHealth>;
  /** Not a dedicated backend route - derived from the decision field on events today. */
  getDecisions(): Promise<DecisionStatistic[]>;
}

/**
 * Single swap point for the whole dashboard's data source. Returns the mock
 * implementation today; will return a real ApiDashboardService once the
 * backend dashboard endpoints exist. No component should import
 * mockDashboardService directly - always go through this function.
 */
export function getDashboardService(): DashboardService {
  return mockDashboardService;
}
