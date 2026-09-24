import { useCallback, useEffect, useState } from "react";
import { getDashboardService } from "../services/dashboardService";
import type {
  DashboardSummary,
  DecisionStatistic,
  RiskPoint,
  SecurityEvent,
  SystemHealth,
  ThreatStatistic,
  TrafficPoint,
} from "../types/dashboard";

interface DashboardData {
  summary: DashboardSummary;
  threats: ThreatStatistic[];
  events: SecurityEvent[];
  traffic: TrafficPoint[];
  risk: RiskPoint[];
  health: SystemHealth;
  decisions: DecisionStatistic[];
}

interface UseDashboardDataResult {
  data: DashboardData | null;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

/**
 * Fetches every slice of dashboard data the current page needs via the
 * DashboardService abstraction (mock today, a real backend later - this hook
 * does not know or care which). Pages/components only ever see this hook's
 * output, never the service directly.
 */
export function useDashboardData(): UseDashboardDataResult {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => {
    setRefreshToken((token) => token + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const service = getDashboardService();

    setLoading(true);
    setError(null);

    Promise.all([
      service.getSummary(),
      service.getThreats(),
      service.getEvents(),
      service.getTraffic(),
      service.getRisk(),
      service.getHealth(),
      service.getDecisions(),
    ])
      .then(([summary, threats, events, traffic, risk, health, decisions]) => {
        if (cancelled) return;
        setData({ summary, threats, events, traffic, risk, health, decisions });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load dashboard data");
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [refreshToken]);

  return { data, loading, error, refresh };
}
