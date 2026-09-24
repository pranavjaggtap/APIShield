import type {
  ApiRequestConfig,
  ApiResponseResult,
  KeyValuePair,
  SecurityEventErrorKind,
  SecurityEventPage,
  SecurityEventQuery,
  SecurityEventRecord,
  SecurityInference,
} from "../types/apiConsole";

/**
 * The console never accepts a full external URL - only a path is editable,
 * and it must stay under /api/ so it can only ever reach APIShield's own
 * configured gateway route. The actual network call goes to this relative
 * path, which Vite's dev server proxy (vite.config.ts) forwards to
 * http://localhost:8080. This is informational only, for display in the URL
 * bar - it is never interpolated into the fetch target itself.
 */
export const GATEWAY_ORIGIN_DISPLAY = "http://localhost:8080";

export const REQUIRED_PATH_PREFIX = "/api/";

/**
 * Header names the Fetch spec (or, for User-Agent, unreliable cross-browser
 * behavior) prevents JavaScript from setting. Attempting to set these via
 * fetch() either throws, is silently stripped by the browser, or is
 * overridden by the network layer regardless of what the page requests -
 * offering them as if they'd really be sent would be dishonest. Validated
 * before send so the user sees why, rather than a silently-ignored header.
 */
const FORBIDDEN_HEADER_NAMES = new Set(
  [
    "accept-charset",
    "accept-encoding",
    "access-control-request-headers",
    "access-control-request-method",
    "connection",
    "content-length",
    "cookie",
    "cookie2",
    "date",
    "dnt",
    "expect",
    "host",
    "keep-alive",
    "origin",
    "referer",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
    "user-agent",
  ].map((name) => name.toLowerCase()),
);

const FORBIDDEN_HEADER_PREFIXES = ["proxy-", "sec-"];

export function isForbiddenHeaderName(name: string): boolean {
  const lower = name.trim().toLowerCase();
  if (FORBIDDEN_HEADER_NAMES.has(lower)) return true;
  return FORBIDDEN_HEADER_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export function forbiddenHeaderReason(name: string): string {
  const lower = name.trim().toLowerCase();
  if (lower === "user-agent") {
    return "Browsers restrict scripts from setting User-Agent - this header will not actually be sent as typed.";
  }
  return "Browsers block JavaScript from setting this header for security reasons - it will not actually be sent.";
}

function enabledEntries(pairs: KeyValuePair[]): [string, string][] {
  return pairs
    .filter((pair) => pair.enabled && pair.key.trim().length > 0)
    .map((pair) => [pair.key.trim(), pair.value] as [string, string]);
}

export function buildRequestUrl(config: ApiRequestConfig): string {
  const query = new URLSearchParams();
  for (const [key, value] of enabledEntries(config.queryParams)) {
    query.append(key, value);
  }
  const queryString = query.toString();
  return queryString ? `${config.path}?${queryString}` : config.path;
}

export interface SendRequestError {
  message: string;
}

export interface ApiRequestService {
  send(config: ApiRequestConfig): Promise<ApiResponseResult>;
}

/**
 * The one implementation - there is no mock variant here, unlike the
 * dashboard's service abstraction. The console's entire purpose is to make a
 * real request through the real gateway from day one.
 */
export const apiRequestService: ApiRequestService = {
  async send(config: ApiRequestConfig): Promise<ApiResponseResult> {
    const url = buildRequestUrl(config);
    const headers = new Headers();
    for (const [key, value] of enabledEntries(config.headers)) {
      if (isForbiddenHeaderName(key)) continue; // validated earlier in the UI; skip defensively
      headers.set(key, value);
    }

    const hasBody = (config.method === "POST" || config.method === "PUT") && config.body.trim().length > 0;
    if (hasBody && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const startedAt = performance.now();
    const response = await fetch(url, {
      method: config.method,
      headers,
      body: hasBody ? config.body : undefined,
    });
    const durationMs = performance.now() - startedAt;

    const bodyText = await response.text();
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: bodyText,
      durationMs,
      timestamp: new Date().toISOString(),
    };
  },
};

/** The exact message SecurityGatewayFilter.BLOCK_BODY writes on a block decision. */
const APISHIELD_BLOCK_MESSAGE = "Request blocked by APIShield";

/**
 * Honest inference from a real response only - see the type doc comment for
 * why this never includes a threat type or risk score. A 403 with any other
 * body is deliberately NOT inferred as BLOCKED, since only this exact,
 * known APIShield response shape can be attributed to the security pipeline
 * rather than some other cause of a 403.
 */
export function inferSecurityResult(result: ApiResponseResult | null): SecurityInference {
  if (!result) return "UNKNOWN";
  if (result.status === 403 && result.body.includes(APISHIELD_BLOCK_MESSAGE)) {
    return "BLOCKED";
  }
  return "NOT_BLOCKED";
}

// --- Security Event API ------------------------------------------------------------------------

export const SECURITY_EVENTS_PATH = "/api/security/events";

/** The backend rejects sizes above this (SecurityEventController.MAX_PAGE_SIZE). */
export const SECURITY_EVENTS_MAX_PAGE_SIZE = 100;

export class SecurityEventApiError extends Error {
  readonly kind: SecurityEventErrorKind;
  readonly status: number | null;

  constructor(kind: SecurityEventErrorKind, status: number | null, message: string) {
    super(message);
    this.name = "SecurityEventApiError";
    this.kind = kind;
    this.status = status;
  }
}

/**
 * Accepts either a bare JWT or a pasted "Bearer <jwt>" value and returns the
 * bare token, so the header is never sent as "Bearer Bearer ...".
 */
export function normalizeAccessToken(input: string): string {
  return input.trim().replace(/^bearer\s+/i, "").trim();
}

/** Only a shape hint for the UI - the token is actually validated by APIShield, never here. */
export function looksLikeJwt(token: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(token);
}

/**
 * Explains a 401 using the RFC 6750 WWW-Authenticate header APIShield sends:
 * `Bearer error="invalid_token"` means the token itself was rejected; a bare
 * `Bearer` means no usable token was received. The token is never echoed.
 */
function unauthorizedMessage(wwwAuthenticate: string | null): string {
  if (wwwAuthenticate && /error="invalid_token"/i.test(wwwAuthenticate)) {
    return "APIShield rejected the access token - it is malformed, expired, or not signed by the configured issuer.";
  }
  return "APIShield did not accept the request as authenticated. Check the access token - and note that APIShield rejects every token until a JWT issuer/JWK is configured on the backend.";
}

const UNREACHABLE_MESSAGE =
  "Could not reach APIShield - is it running on port 8080 (and is the Vite dev server proxying /api/)?";

/**
 * Statuses a proxy in front of APIShield returns when APIShield itself is down (in development the
 * Vite proxy answers 502 with an empty body). APIShield's own Security Event API never sends these.
 */
const UPSTREAM_UNAVAILABLE_STATUSES = new Set([502, 503, 504]);

async function fetchSecurityEventJson<T>(url: string, accessToken: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${accessToken}` },
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new SecurityEventApiError("NETWORK", null, UNREACHABLE_MESSAGE);
  }

  if (UPSTREAM_UNAVAILABLE_STATUSES.has(response.status)) {
    throw new SecurityEventApiError("NETWORK", response.status, `${UNREACHABLE_MESSAGE} (HTTP ${response.status})`);
  }
  if (response.status === 401) {
    throw new SecurityEventApiError("UNAUTHORIZED", 401, unauthorizedMessage(response.headers.get("WWW-Authenticate")));
  }
  if (response.status === 404) {
    throw new SecurityEventApiError("NOT_FOUND", 404, "This security event no longer exists.");
  }
  if (response.status === 400) {
    throw new SecurityEventApiError("BAD_REQUEST", 400, "APIShield rejected the request parameters (page, size or decision).");
  }
  if (!response.ok) {
    throw new SecurityEventApiError(
      "SERVER",
      response.status,
      `APIShield returned HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}.`,
    );
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new SecurityEventApiError("SERVER", response.status, "APIShield returned a response that is not valid JSON.");
  }
}

export interface SecurityEventService {
  /** GET /api/security/events - newest first. */
  list(query: SecurityEventQuery, accessToken: string, signal?: AbortSignal): Promise<SecurityEventPage>;
  /** GET /api/security/events/{id} */
  get(id: string, accessToken: string, signal?: AbortSignal): Promise<SecurityEventRecord>;
}

/**
 * Real calls to APIShield's read-only Security Event API, through the same
 * Vite /api/ proxy as the console. Like the console, there is no mock variant:
 * every event shown comes from the backend. Errors are always thrown as
 * SecurityEventApiError, except AbortError, which is rethrown untouched so
 * callers can ignore superseded requests.
 */
export const securityEventService: SecurityEventService = {
  async list(query, accessToken, signal) {
    const params = new URLSearchParams({ page: String(query.page), size: String(query.size) });
    if (query.decision) params.set("decision", query.decision);

    const page = await fetchSecurityEventJson<SecurityEventPage>(
      `${SECURITY_EVENTS_PATH}?${params.toString()}`,
      accessToken,
      signal,
    );
    if (!page || !Array.isArray(page.content)) {
      throw new SecurityEventApiError("SERVER", null, "APIShield returned an unexpected security event list format.");
    }
    return page;
  },

  async get(id, accessToken, signal) {
    return fetchSecurityEventJson<SecurityEventRecord>(
      `${SECURITY_EVENTS_PATH}/${encodeURIComponent(id)}`,
      accessToken,
      signal,
    );
  },
};
