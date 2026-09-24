import { Lock } from "lucide-react";
import { GATEWAY_ORIGIN_DISPLAY, REQUIRED_PATH_PREFIX } from "../../services/apiRequestService";
import { cn } from "../../lib/cn";

interface UrlBarProps {
  path: string;
  onChange: (path: string) => void;
  error: string | null;
}

/**
 * The origin is fixed, read-only display text - never an input - so the
 * console structurally cannot be pointed at anything other than APIShield's
 * own local gateway. Only the path is editable, and is validated to stay
 * under /api/.
 */
export function UrlBar({ path, onChange, error }: UrlBarProps) {
  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-2 rounded-lg border bg-surface-raised px-3 py-2.5 transition-colors",
          error ? "border-danger/40" : "border-border focus-within:border-primary/40",
        )}
      >
        <span className="flex items-center gap-1.5 whitespace-nowrap text-sm text-text-muted" title="Fixed to the APIShield local gateway - not editable">
          <Lock className="h-3.5 w-3.5" strokeWidth={1.75} />
          {GATEWAY_ORIGIN_DISPLAY}
        </span>
        <input
          value={path}
          onChange={(event) => onChange(event.target.value)}
          spellCheck={false}
          aria-label="Request path"
          placeholder={`${REQUIRED_PATH_PREFIX}users/1`}
          className="min-w-0 flex-1 bg-transparent font-mono text-sm text-text-primary outline-none placeholder:text-text-muted"
        />
      </div>
      {error && <p className="mt-1.5 text-xs text-danger">{error}</p>}
    </div>
  );
}
