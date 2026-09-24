import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, Send } from "lucide-react";
import { TopHeader } from "../components/layout/TopHeader";
import { Card } from "../components/common/Card";
import { MethodSelector } from "../components/api-console/MethodSelector";
import { UrlBar } from "../components/api-console/UrlBar";
import { KeyValueEditor } from "../components/api-console/KeyValueEditor";
import { RequestBodyEditor } from "../components/api-console/RequestBodyEditor";
import { ResponsePanel } from "../components/api-console/ResponsePanel";
import { SecurityResultPanel } from "../components/api-console/SecurityResultPanel";
import { RequestHistory } from "../components/api-console/RequestHistory";
import { QuickTests } from "../components/api-console/QuickTests";
import { SecurityEventsPanel } from "../components/api-console/SecurityEventsPanel";
import {
  apiRequestService,
  forbiddenHeaderReason,
  inferSecurityResult,
  isForbiddenHeaderName,
  REQUIRED_PATH_PREFIX,
} from "../services/apiRequestService";
import type { ApiRequestConfig, ApiResponseResult, RequestHistoryEntry, SecurityInference } from "../types/apiConsole";

function defaultConfig(): ApiRequestConfig {
  return {
    method: "GET",
    path: "/api/users/1",
    queryParams: [],
    headers: [],
    body: "",
  };
}

/**
 * APIShield persists security events in the background after responding, so an event is usually
 * not readable the instant the response arrives. The events list is refreshed after this delay;
 * the panel's Refresh button covers anything slower.
 */
const EVENTS_REFRESH_DELAY_MS = 750;

function validatePath(path: string): string | null {
  if (!path.trim().startsWith(REQUIRED_PATH_PREFIX)) {
    return `Path must start with ${REQUIRED_PATH_PREFIX} - that is the only route currently configured on the APIShield gateway.`;
  }
  return null;
}

export function ApiConsolePage() {
  const [config, setConfig] = useState<ApiRequestConfig>(defaultConfig());
  const [response, setResponse] = useState<ApiResponseResult | null>(null);
  const [securityInference, setSecurityInference] = useState<SecurityInference | null>(null);
  const [loading, setLoading] = useState(false);
  const [networkError, setNetworkError] = useState<string | null>(null);
  const [pathError, setPathError] = useState<string | null>(null);
  const [bodyError, setBodyError] = useState<string | null>(null);
  const [history, setHistory] = useState<RequestHistoryEntry[]>([]);
  const [eventsRefreshKey, setEventsRefreshKey] = useState(0);

  // Synchronous guard against duplicate submission from a rapid double-click,
  // independent of React's async state batching.
  const isSendingRef = useRef(false);
  const eventsRefreshTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (eventsRefreshTimerRef.current !== null) window.clearTimeout(eventsRefreshTimerRef.current);
    };
  }, []);

  function scheduleEventsRefresh() {
    if (eventsRefreshTimerRef.current !== null) window.clearTimeout(eventsRefreshTimerRef.current);
    eventsRefreshTimerRef.current = window.setTimeout(() => {
      eventsRefreshTimerRef.current = null;
      setEventsRefreshKey((key) => key + 1);
    }, EVENTS_REFRESH_DELAY_MS);
  }

  const showBody = config.method === "POST" || config.method === "PUT";

  const addHistoryEntry = useCallback(
    (entry: Omit<RequestHistoryEntry, "id" | "timestamp">) => {
      setHistory((prev) => [{ id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...entry }, ...prev]);
    },
    [],
  );

  async function handleSend() {
    if (isSendingRef.current) return;

    const nextPathError = validatePath(config.path);
    setPathError(nextPathError);
    if (nextPathError) return;

    let nextBodyError: string | null = null;
    if (showBody && config.body.trim()) {
      try {
        JSON.parse(config.body);
      } catch (error) {
        nextBodyError = `Invalid JSON: ${error instanceof Error ? error.message : "could not parse body"}`;
      }
    }
    setBodyError(nextBodyError);
    if (nextBodyError) return;

    isSendingRef.current = true;
    setLoading(true);
    setNetworkError(null);

    try {
      const result = await apiRequestService.send(config);
      const inference = inferSecurityResult(result);
      setResponse(result);
      setSecurityInference(inference);
      addHistoryEntry({
        method: config.method,
        path: config.path,
        status: result.status,
        securityInference: inference,
        durationMs: result.durationMs,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown network error";
      setResponse(null);
      setSecurityInference("UNKNOWN");
      setNetworkError(`Could not reach the APIShield gateway - is it running on port 8080? (${message})`);
      addHistoryEntry({
        method: config.method,
        path: config.path,
        status: null,
        securityInference: "UNKNOWN",
        durationMs: 0,
      });
    } finally {
      setLoading(false);
      isSendingRef.current = false;
      scheduleEventsRefresh();
    }
  }

  return (
    <div className="flex flex-1 flex-col">
      <TopHeader
        title="API Console"
        description="Send real requests through the APIShield gateway and see how the security pipeline responds."
      />

      <main className="flex flex-1 flex-col gap-5 px-8 py-6">
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <Card title="Request Builder" description="Requests are sent through the local APIShield gateway only" className="xl:col-span-2">
            <div className="flex flex-col gap-5">
              <div className="flex flex-col gap-3 sm:flex-row">
                <MethodSelector value={config.method} onChange={(method) => setConfig((c) => ({ ...c, method }))} />
                <div className="flex-1">
                  <UrlBar
                    path={config.path}
                    onChange={(path) => setConfig((c) => ({ ...c, path }))}
                    error={pathError}
                  />
                </div>
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-text-secondary">Query Parameters</p>
                <KeyValueEditor
                  rows={config.queryParams}
                  onChange={(queryParams) => setConfig((c) => ({ ...c, queryParams }))}
                  keyPlaceholder="key"
                  valuePlaceholder="value"
                  addLabel="Add parameter"
                />
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-text-secondary">Headers</p>
                <KeyValueEditor
                  rows={config.headers}
                  onChange={(headers) => setConfig((c) => ({ ...c, headers }))}
                  keyPlaceholder="Header"
                  valuePlaceholder="Value"
                  addLabel="Add header"
                  validateKey={(key) => (isForbiddenHeaderName(key) ? forbiddenHeaderReason(key) : null)}
                />
              </div>

              {showBody && (
                <div>
                  <p className="mb-2 text-xs font-medium text-text-secondary">Request Body (JSON)</p>
                  <RequestBodyEditor
                    value={config.body}
                    onChange={(body) => setConfig((c) => ({ ...c, body }))}
                    error={bodyError}
                  />
                </div>
              )}

              <button
                type="button"
                onClick={handleSend}
                disabled={loading}
                className="flex items-center justify-center gap-2 self-start rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-primary-muted disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    APIShield is analyzing the request…
                  </>
                ) : (
                  <>
                    <Send className="h-4 w-4" />
                    Send Request
                  </>
                )}
              </button>
            </div>
          </Card>

          <Card title="Quick Security Tests" description="Fills the form only - press Send to actually test it">
            <QuickTests
              onSelect={(nextConfig) => {
                setConfig(nextConfig);
                setPathError(null);
                setBodyError(null);
              }}
            />
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <Card title="Response" description="The real HTTP response from APIShield" className="xl:col-span-2">
            <ResponsePanel result={response} loading={loading} networkError={networkError} />
          </Card>

          <Card title="Security Result" description="Inferred only from the real response">
            <SecurityResultPanel inference={securityInference} />
          </Card>
        </div>

        <Card title="Request History" description="Requests sent during this browser session">
          <RequestHistory entries={history} />
        </Card>

        <SecurityEventsPanel refreshKey={eventsRefreshKey} />
      </main>
    </div>
  );
}
