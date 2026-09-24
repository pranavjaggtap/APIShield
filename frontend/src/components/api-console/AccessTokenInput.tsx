import { useState, type FormEvent } from "react";
import { Eye, EyeOff, KeyRound, X } from "lucide-react";
import { looksLikeJwt, normalizeAccessToken } from "../../services/apiRequestService";
import { StatusDot } from "../common/StatusDot";
import { cn } from "../../lib/cn";

interface AccessTokenInputProps {
  activeToken: string | null;
  /** True once APIShield has answered 401 for the active token. */
  tokenRejected: boolean;
  onApply: (token: string) => void;
  onClear: () => void;
}

/**
 * Where the user supplies the JWT the Security Event API requires. APIShield does not issue
 * tokens and the frontend has no login flow, so the token comes from whatever identity provider
 * APIShield is configured to trust. It is held in React memory only - never written to
 * localStorage/sessionStorage - and is gone on page refresh.
 */
export function AccessTokenInput({ activeToken, tokenRejected, onApply, onClear }: AccessTokenInputProps) {
  const [draft, setDraft] = useState("");
  const [revealed, setRevealed] = useState(false);

  const normalizedDraft = normalizeAccessToken(draft);
  const shapeWarning =
    normalizedDraft && !looksLikeJwt(normalizedDraft)
      ? "This does not look like a JWT (header.payload.signature) - APIShield will most likely reject it."
      : null;

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!normalizedDraft) return;
    onApply(normalizedDraft);
    setDraft("");
    setRevealed(false);
  }

  return (
    <div className="flex flex-col gap-2">
      <form onSubmit={handleSubmit} className="flex flex-col gap-2 sm:flex-row">
        <div
          className={cn(
            "flex min-w-0 flex-1 items-center gap-2 rounded-lg border bg-surface-raised px-3 py-2 transition-colors",
            shapeWarning ? "border-warning/40" : "border-border focus-within:border-primary/40",
          )}
        >
          <KeyRound className="h-3.5 w-3.5 shrink-0 text-text-muted" strokeWidth={1.75} />
          <input
            type={revealed ? "text" : "password"}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder={activeToken ? "Paste a different token to replace the current one" : "Paste a Bearer JWT"}
            aria-label="Access token"
            autoComplete="off"
            spellCheck={false}
            className="min-w-0 flex-1 bg-transparent font-mono text-xs text-text-primary outline-none placeholder:text-text-muted"
          />
          <button
            type="button"
            onClick={() => setRevealed((value) => !value)}
            aria-label={revealed ? "Hide token" : "Show token"}
            className="shrink-0 text-text-muted transition-colors hover:text-text-secondary"
          >
            {revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </button>
        </div>
        <button
          type="submit"
          disabled={!normalizedDraft}
          className="rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-primary-muted disabled:cursor-not-allowed disabled:opacity-50"
        >
          {activeToken ? "Replace token" : "Use token"}
        </button>
      </form>

      {shapeWarning && <p className="text-[11px] text-warning">{shapeWarning}</p>}

      <div className="flex flex-wrap items-center justify-between gap-2">
        {activeToken ? (
          <StatusDot
            tone={tokenRejected ? "down" : "operational"}
            label={
              tokenRejected
                ? "Access token rejected by APIShield - replace or clear it"
                : "Access token applied - kept in memory for this tab only"
            }
            pulse={false}
          />
        ) : (
          <p className="text-[11px] text-text-muted">
            Required by <span className="font-mono">/api/security/events</span>. Held in memory only, never stored.
          </p>
        )}
        {activeToken && (
          <button
            type="button"
            onClick={onClear}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-text-muted transition-colors hover:bg-danger/10 hover:text-danger"
          >
            <X className="h-3 w-3" />
            Clear token
          </button>
        )}
      </div>
    </div>
  );
}
