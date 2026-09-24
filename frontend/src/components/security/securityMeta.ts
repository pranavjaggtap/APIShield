import { Bot, Database, Gauge, Repeat, ShieldQuestion, SquareCode } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { BadgeColor } from "../common/Badge";
import type { DecisionOutcome, Severity, ThreatType } from "../../types/dashboard";

/**
 * Single source of truth for how each threat type / decision / severity is
 * labeled, iconified, and colored. Every badge, table row, and chart on the
 * dashboard reads from here so the same threat type or decision always looks
 * identical everywhere it appears.
 */

interface ThreatMeta {
  label: string;
  icon: LucideIcon;
  /** Literal hex, not a Tailwind class - Recharts SVG fill props need a real color value. */
  chartColor: string;
}

export const THREAT_META: Record<ThreatType, ThreatMeta> = {
  SQL_INJECTION: { label: "SQL Injection", icon: Database, chartColor: "#3b82f6" },
  XSS: { label: "XSS", icon: SquareCode, chartColor: "#8b5cf6" },
  REPLAY_ATTACK: { label: "Replay Attack", icon: Repeat, chartColor: "#22d3ee" },
  FREQUENCY_ABUSE: { label: "Frequency Abuse", icon: Gauge, chartColor: "#f97316" },
  BOT_AUTOMATION: { label: "Bot Automation", icon: Bot, chartColor: "#f59e0b" },
};

export const NO_THREAT_META: ThreatMeta = { label: "None", icon: ShieldQuestion, chartColor: "#334155" };

interface DecisionMeta {
  label: string;
  color: BadgeColor;
  chartColor: string;
}

export const DECISION_META: Record<DecisionOutcome, DecisionMeta> = {
  ALLOW: { label: "ALLOW", color: "success", chartColor: "#10b981" },
  MONITOR: { label: "MONITOR", color: "warning", chartColor: "#f59e0b" },
  BLOCK: { label: "BLOCK", color: "danger", chartColor: "#ef4444" },
};

interface SeverityMeta {
  label: string;
  color: BadgeColor;
  dotClassName: string;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  LOW: { label: "Low", color: "secondary", dotClassName: "bg-secondary" },
  MEDIUM: { label: "Medium", color: "warning", dotClassName: "bg-warning" },
  HIGH: { label: "High", color: "orange", dotClassName: "bg-orange" },
  CRITICAL: { label: "Critical", color: "critical", dotClassName: "bg-critical" },
};

export function riskBadgeColor(riskScore: number): BadgeColor {
  if (riskScore >= 0.8) return "critical";
  if (riskScore >= 0.5) return "danger";
  if (riskScore >= 0.3) return "warning";
  return "success";
}
