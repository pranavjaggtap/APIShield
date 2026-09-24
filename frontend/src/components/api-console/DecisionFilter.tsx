import type { SecurityEventDecision } from "../../types/apiConsole";
import { cn } from "../../lib/cn";

/** The values APIShield's `decision` filter accepts (Decision.Outcome on the backend). */
const OPTIONS: { value: SecurityEventDecision | null; label: string; activeClass: string }[] = [
  { value: null, label: "All", activeClass: "bg-primary/15 text-primary border-primary/30" },
  { value: "ALLOW", label: "Allowed", activeClass: "bg-success/15 text-success border-success/30" },
  { value: "BLOCK", label: "Blocked", activeClass: "bg-danger/15 text-danger border-danger/30" },
];

interface DecisionFilterProps {
  value: SecurityEventDecision | null;
  onChange: (value: SecurityEventDecision | null) => void;
  disabled?: boolean;
}

export function DecisionFilter({ value, onChange, disabled }: DecisionFilterProps) {
  return (
    <div className="flex gap-1 rounded-lg border border-border bg-surface-raised p-1" role="radiogroup" aria-label="Filter by decision">
      {OPTIONS.map((option) => {
        const isActive = value === option.value;
        return (
          <button
            key={option.label}
            type="button"
            role="radio"
            aria-checked={isActive}
            disabled={disabled}
            onClick={() => onChange(option.value)}
            className={cn(
              "rounded-md border border-transparent px-2.5 py-1 text-xs font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50",
              isActive ? option.activeClass : "text-text-muted hover:text-text-secondary",
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
