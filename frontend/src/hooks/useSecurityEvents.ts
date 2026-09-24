import { useEffect, useState } from "react";
import { SecurityEventApiError, securityEventService } from "../services/apiRequestService";
import type { SecurityEventDecision, SecurityEventPage, SecurityEventRecord } from "../types/apiConsole";

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function toApiError(error: unknown): SecurityEventApiError {
  if (error instanceof SecurityEventApiError) return error;
  return new SecurityEventApiError("SERVER", null, error instanceof Error ? error.message : "Unexpected error");
}

// Each hook tags its stored result with the request it belongs to ("key"). Loading is derived by
// comparing that tag with the current request instead of being set synchronously in the effect,
// and a superseded in-flight request is aborted so a slow earlier response can never overwrite a
// newer one. The access token is only ever held in memory.

interface ListState {
  key: string;
  page: SecurityEventPage | null;
  error: SecurityEventApiError | null;
}

function listKey(page: number, size: number, decision: SecurityEventDecision | null, refreshKey: number, token: string) {
  return JSON.stringify([page, size, decision, refreshKey, token]);
}

interface UseSecurityEventListResult {
  /** The latest successfully loaded page - kept visible while the next one loads. */
  page: SecurityEventPage | null;
  error: SecurityEventApiError | null;
  loading: boolean;
}

/**
 * Loads one page of security events. Does nothing until an access token is provided: the API
 * always requires one, so calling without it could only ever produce a 401. Changing
 * `refreshKey` re-fetches the same page.
 */
export function useSecurityEventList(
  page: number,
  size: number,
  decision: SecurityEventDecision | null,
  refreshKey: number,
  accessToken: string | null,
): UseSecurityEventListResult {
  const [state, setState] = useState<ListState | null>(null);
  const key = accessToken ? listKey(page, size, decision, refreshKey, accessToken) : null;

  useEffect(() => {
    if (!accessToken) return;
    const requestKey = listKey(page, size, decision, refreshKey, accessToken);
    const controller = new AbortController();

    securityEventService
      .list({ page, size, decision }, accessToken, controller.signal)
      .then((result) => setState({ key: requestKey, page: result, error: null }))
      .catch((error: unknown) => {
        if (isAbort(error)) return;
        setState((previous) => ({ key: requestKey, page: previous?.page ?? null, error: toApiError(error) }));
      });

    return () => controller.abort();
  }, [page, size, decision, refreshKey, accessToken]);

  const isCurrent = key !== null && state?.key === key;
  return {
    page: key === null ? null : (state?.page ?? null),
    error: isCurrent ? state.error : null,
    loading: key !== null && !isCurrent,
  };
}

interface EventState {
  key: string;
  event: SecurityEventRecord | null;
  error: SecurityEventApiError | null;
}

interface UseSecurityEventResult {
  event: SecurityEventRecord | null;
  error: SecurityEventApiError | null;
  loading: boolean;
}

/** Loads a single event by id (GET /api/security/events/{id}). Inactive while id or token is null. */
export function useSecurityEvent(id: string | null, accessToken: string | null): UseSecurityEventResult {
  const [state, setState] = useState<EventState | null>(null);
  const key = id && accessToken ? JSON.stringify([id, accessToken]) : null;

  useEffect(() => {
    if (!id || !accessToken) return;
    const requestKey = JSON.stringify([id, accessToken]);
    const controller = new AbortController();

    securityEventService
      .get(id, accessToken, controller.signal)
      .then((result) => setState({ key: requestKey, event: result, error: null }))
      .catch((error: unknown) => {
        if (isAbort(error)) return;
        setState({ key: requestKey, event: null, error: toApiError(error) });
      });

    return () => controller.abort();
  }, [id, accessToken]);

  const isCurrent = key !== null && state?.key === key;
  return {
    event: isCurrent ? state.event : null,
    error: isCurrent ? state.error : null,
    loading: key !== null && !isCurrent,
  };
}
