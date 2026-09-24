import { Plus, Trash2 } from "lucide-react";
import type { KeyValuePair } from "../../types/apiConsole";
import { cn } from "../../lib/cn";

interface KeyValueEditorProps {
  rows: KeyValuePair[];
  onChange: (rows: KeyValuePair[]) => void;
  keyPlaceholder: string;
  valuePlaceholder: string;
  addLabel: string;
  /** Returns a warning message for a row's key, or null if it's fine. */
  validateKey?: (key: string) => string | null;
}

function emptyRow(): KeyValuePair {
  return { id: crypto.randomUUID(), key: "", value: "", enabled: true };
}

/**
 * Shared by both the query parameter builder and the header builder - same
 * add/remove/edit/enable-toggle shape in both places, so this is one
 * component rather than two near-duplicates.
 */
export function KeyValueEditor({ rows, onChange, keyPlaceholder, valuePlaceholder, addLabel, validateKey }: KeyValueEditorProps) {
  function updateRow(id: string, patch: Partial<KeyValuePair>) {
    onChange(rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  function removeRow(id: string) {
    onChange(rows.filter((row) => row.id !== id));
  }

  function addRow() {
    onChange([...rows, emptyRow()]);
  }

  return (
    <div className="flex flex-col gap-2">
      {rows.map((row) => {
        const warning = row.key.trim() ? validateKey?.(row.key) ?? null : null;
        return (
          <div key={row.id}>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={row.enabled}
                onChange={(event) => updateRow(row.id, { enabled: event.target.checked })}
                aria-label={`Enable row`}
                className="h-3.5 w-3.5 shrink-0 accent-primary"
              />
              <input
                value={row.key}
                onChange={(event) => updateRow(row.id, { key: event.target.value })}
                placeholder={keyPlaceholder}
                spellCheck={false}
                className={cn(
                  "min-w-0 flex-1 rounded-md border bg-surface-raised px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none placeholder:text-text-muted",
                  warning ? "border-warning/40" : "border-border focus:border-primary/40",
                )}
              />
              <input
                value={row.value}
                onChange={(event) => updateRow(row.id, { value: event.target.value })}
                placeholder={valuePlaceholder}
                spellCheck={false}
                className="min-w-0 flex-1 rounded-md border border-border bg-surface-raised px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none placeholder:text-text-muted focus:border-primary/40"
              />
              <button
                type="button"
                onClick={() => removeRow(row.id)}
                aria-label="Remove row"
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-text-muted transition-colors hover:bg-danger/10 hover:text-danger"
              >
                <Trash2 className="h-3.5 w-3.5" strokeWidth={1.75} />
              </button>
            </div>
            {warning && <p className="ml-6 mt-1 text-[11px] text-warning">{warning}</p>}
          </div>
        );
      })}

      <button
        type="button"
        onClick={addRow}
        className="mt-1 flex items-center gap-1.5 self-start rounded-md border border-dashed border-border-strong px-2.5 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:border-primary/40 hover:text-primary"
      >
        <Plus className="h-3.5 w-3.5" strokeWidth={2} />
        {addLabel}
      </button>
    </div>
  );
}
