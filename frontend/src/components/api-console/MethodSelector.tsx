import type { HttpMethod } from "../../types/apiConsole";
import { cn } from "../../lib/cn";

const METHODS: { method: HttpMethod; activeClass: string }[] = [
  { method: "GET", activeClass: "bg-success/15 text-success border-success/30" },
  { method: "POST", activeClass: "bg-warning/15 text-warning border-warning/30" },
  { method: "PUT", activeClass: "bg-primary/15 text-primary border-primary/30" },
  { method: "DELETE", activeClass: "bg-danger/15 text-danger border-danger/30" },
];

interface MethodSelectorProps {
  value: HttpMethod;
  onChange: (method: HttpMethod) => void;
}

export function MethodSelector({ value, onChange }: MethodSelectorProps) {
  return (
    <div className="flex gap-1 rounded-lg border border-border bg-surface-raised p-1" role="radiogroup" aria-label="HTTP method">
      {METHODS.map(({ method, activeClass }) => {
        const isActive = value === method;
        return (
          <button
            key={method}
            type="button"
            role="radio"
            aria-checked={isActive}
            onClick={() => onChange(method)}
            className={cn(
              "rounded-md border border-transparent px-3 py-1.5 font-mono text-xs font-semibold transition-colors duration-150",
              isActive ? activeClass : "text-text-muted hover:text-text-secondary",
            )}
          >
            {method}
          </button>
        );
      })}
    </div>
  );
}
