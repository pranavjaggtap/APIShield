interface RequestBodyEditorProps {
  value: string;
  onChange: (value: string) => void;
  error: string | null;
}

/**
 * A plain, clean textarea - deliberately not a full code-editor dependency
 * (Monaco/CodeMirror). JSON validity is checked by the parent on every
 * change and surfaced here as an inline error, not enforced by the editor
 * itself.
 */
export function RequestBodyEditor({ value, onChange, error }: RequestBodyEditorProps) {
  return (
    <div>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        spellCheck={false}
        rows={8}
        placeholder={'{\n  "name": "John",\n  "email": "john@example.com"\n}'}
        className={
          "w-full resize-y rounded-lg border bg-surface-raised px-3 py-2.5 font-mono text-xs leading-relaxed text-text-primary outline-none placeholder:text-text-muted " +
          (error ? "border-danger/40" : "border-border focus:border-primary/40")
        }
      />
      {error && <p className="mt-1.5 text-xs text-danger">{error}</p>}
    </div>
  );
}
