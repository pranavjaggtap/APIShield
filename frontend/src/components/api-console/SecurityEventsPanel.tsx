import { useState } from "react";
import { KeyRound, RotateCw, ShieldAlert, ShieldCheck } from "lucide-react";
import type { SecurityEventDecision, SecurityEventRecord } from "../../types/apiConsole";
import { useSecurityEventList } from "../../hooks/useSecurityEvents";
import { cn } from "../../lib/cn";
import { Card } from "../common/Card";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { AccessTokenInput } from "./AccessTokenInput";
import { DecisionFilter } from "./DecisionFilter";
import { SecurityEventDetails } from "./SecurityEventDetails";
import { SecurityEventsPagination } from "./SecurityEventsPagination";
import { SecurityEventsTable } from "./SecurityEventsTable";

const DEFAULT_PAGE_SIZE = 20;

interface SecurityEventsPanelProps {
  /** Incremented by the parent to re-fetch the current page (e.g. after a console request). */
  refreshKey: number;
  /** Notified when the token is applied or cleared, so the parent can reuse it (e.g. the API Console). */
  onAccessTokenChange?: (token: string | null) => void;
}

/**
 * The persisted results of APIShield's security pipeline, read from GET /api/security/events and
 * GET /api/security/events/{id}. Every row comes from the backend - nothing here is generated.
 */
export function SecurityEventsPanel({ refreshKey, onAccessTokenChange }: SecurityEventsPanelProps) {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(DEFAULT_PAGE_SIZE);
  const [decision, setDecision] = useState<SecurityEventDecision | null>(null);
  const [manualRefresh, setManualRefresh] = useState(0);
  const [selected, setSelected] = useState<SecurityEventRecord | null>(null);

  const list = useSecurityEventList(page, size, decision, refreshKey + manualRefresh, accessToken);
  const data = list.page;

  function applyToken(token: string) {
    setAccessToken(token);
    setSelected(null);
    onAccessTokenChange?.(token);
  }

  function clearToken() {
    setAccessToken(null);
    setSelected(null);
    onAccessTokenChange?.(null);
  }

  function changeDecision(next: SecurityEventDecision | null) {
    setDecision(next);
    setPage(0);
  }

  function changeSize(next: number) {
    setSize(next);
    setPage(0);
  }

  function renderBody() {
    if (!accessToken) {
      return (
        <EmptyState
          icon={KeyRound}
          title="Access token required"
          description="The Security Event API requires a Bearer JWT from the identity provider APIShield trusts. Paste one above to load events."
        />
      );
    }

    if (list.error?.kind === "UNAUTHORIZED") {
      return (
        <div className="flex flex-col items-center gap-3">
          <EmptyState icon={ShieldAlert} title="Not authorized" description={list.error.message} className="pb-0" />
          <button
            type="button"
            onClick={clearToken}
            className="rounded-md border border-border-strong bg-surface-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:border-primary/40 hover:text-text-primary"
          >
            Clear token
          </button>
        </div>
      );
    }

    if (list.error) {
      return <ErrorState message={list.error.message} onRetry={() => setManualRefresh((value) => value + 1)} />;
    }

    if (!data) {
      return <LoadingState rows={6} className="py-6" />;
    }

    if (data.content.length === 0) {
      if (page > 0) {
        return (
          <div className="flex flex-col items-center gap-3">
            <EmptyState title="No events on this page" description="Events may have been removed since this page was loaded." className="pb-0" />
            <button
              type="button"
              onClick={() => setPage(0)}
              className="rounded-md border border-border-strong bg-surface-raised px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:border-primary/40 hover:text-text-primary"
            >
              Go to first page
            </button>
          </div>
        );
      }
      return (
        <EmptyState
          icon={ShieldCheck}
          title={decision ? `No ${decision === "BLOCK" ? "blocked" : "allowed"} events` : "No security events recorded yet"}
          description={
            decision
              ? "No persisted event has this decision."
              : "Send an authenticated request through the gateway above - APIShield records an event for every request its security pipeline evaluates."
          }
        />
      );
    }

    return (
      <div className="flex flex-col gap-3">
        <div className={cn("grid grid-cols-1 gap-4", selected && "min-[1800px]:grid-cols-3")}>
          <div className={cn("min-w-0 transition-opacity", selected && "min-[1800px]:col-span-2", list.loading && "opacity-60")}>
            <SecurityEventsTable events={data.content} selectedId={selected?.id ?? null} onSelect={setSelected} />
          </div>
          {selected && (
            <div className="min-w-0">
              <SecurityEventDetails
                key={selected.id}
                summary={selected}
                accessToken={accessToken}
                onClose={() => setSelected(null)}
              />
            </div>
          )}
        </div>
        <SecurityEventsPagination
          page={data.page}
          size={data.size}
          totalElements={data.totalElements}
          totalPages={data.totalPages}
          shownCount={data.content.length}
          disabled={list.loading}
          onPageChange={setPage}
          onSizeChange={changeSize}
        />
      </div>
    );
  }

  return (
    <Card
      title="Security Events"
      description="Persisted by APIShield for every request its security pipeline evaluated - newest first"
      action={
        <div className="flex flex-wrap items-center gap-2">
          <DecisionFilter value={decision} onChange={changeDecision} disabled={!accessToken} />
          <button
            type="button"
            onClick={() => setManualRefresh((value) => value + 1)}
            disabled={!accessToken || list.loading}
            aria-label="Refresh security events"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface-raised text-text-secondary transition-colors hover:border-primary/40 hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RotateCw className={cn("h-3.5 w-3.5", list.loading && accessToken && "animate-spin")} />
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-5">
        <AccessTokenInput
          activeToken={accessToken}
          tokenRejected={list.error?.kind === "UNAUTHORIZED"}
          onApply={applyToken}
          onClear={clearToken}
        />
        {renderBody()}
      </div>
    </Card>
  );
}
