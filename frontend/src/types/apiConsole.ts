export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface KeyValuePair {
  /** Stable id for React list rendering only - never sent to the server. */
  id: string;
  key: string;
  value: string;
  enabled: boolean;
}

export interface ApiRequestConfig {
  method: HttpMethod;
  /** Always relative to the fixed local gateway origin - never a full external URL. */
  path: string;
  queryParams: KeyValuePair[];
  headers: KeyValuePair[];
  body: string;
}

export interface ApiResponseResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  durationMs: number;
  timestamp: string;
}

/**
 * What can be honestly inferred from an HTTP response alone. The backend does
 * not expose explicit security decision metadata (no custom header, no
 * threat/risk fields in the body) - see apiRequestService.ts for exactly how
 * this is derived. Never a threat type, severity, or risk score: those would
 * be fabricated, not observed.
 */
export type SecurityInference = "BLOCKED" | "NOT_BLOCKED" | "UNKNOWN";

export interface RequestHistoryEntry {
  id: string;
  timestamp: string;
  method: HttpMethod;
  path: string;
  status: number | null;
  securityInference: SecurityInference;
  durationMs: number;
}

// --- Security Event API (GET /api/security/events, GET /api/security/events/{id}) ----------
// These mirror the backend response DTOs exactly - see SecurityEventResponse,
// ThreatSignalResponse and SecurityEventPageResponse in the APIShield backend.

/** Decision values the backend accepts for the `decision` list filter. */
export type SecurityEventDecision = "ALLOW" | "BLOCK";

/** One detector's verdict for the request - clean detectors are included, with detected=false. */
export interface SecurityEventThreatSignal {
  detector: string;
  detected: boolean;
  severity: number;
  description: string;
}

export interface SecurityEventRecord {
  id: string;
  requestId: string;
  /** ISO-8601 instant - when the request reached APIShield. */
  timestamp: string;
  method: string;
  path: string;
  clientIp: string;
  /** JWT `sub` of the caller; null when the request was not authenticated. */
  userId: string | null;
  /** Gateway route the request matched; null when none matched. */
  routeId: string | null;
  /** Kept as a string so a decision value added later on the backend still renders. */
  decision: string;
  decisionReason: string;
  riskScore: number;
  threatScore: number;
  threatSignals: SecurityEventThreatSignal[];
}

/** One newest-first page of events. `page` is zero-based. */
export interface SecurityEventPage {
  content: SecurityEventRecord[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

export interface SecurityEventQuery {
  page: number;
  size: number;
  decision: SecurityEventDecision | null;
}

/**
 * Why a Security Event API call failed, so each case can be shown distinctly:
 * UNAUTHORIZED - 401 (no/invalid/expired token, or no JWT issuer configured on APIShield);
 * NOT_FOUND - 404 for a single event; BAD_REQUEST - 400 (invalid paging/filter);
 * SERVER - any other non-2xx or an unexpected body; NETWORK - APIShield unreachable.
 */
export type SecurityEventErrorKind = "UNAUTHORIZED" | "NOT_FOUND" | "BAD_REQUEST" | "SERVER" | "NETWORK";
