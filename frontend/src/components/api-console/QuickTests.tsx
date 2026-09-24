import { Bug, Repeat, ShieldQuestion, SquareCode } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ApiRequestConfig } from "../../types/apiConsole";

interface QuickTest {
  label: string;
  description: string;
  icon: LucideIcon;
  build: () => ApiRequestConfig;
}

function newRow(key: string, value: string) {
  return { id: crypto.randomUUID(), key, value, enabled: true };
}

const BASE_PATH = "/api/users/1";

/**
 * Each preset only returns a request configuration - it never sends
 * anything itself. Clicking one fills the form; the user still has to press
 * Send Request for a real request to go through APIShield. None of these
 * simulate or fabricate a result.
 */
const QUICK_TESTS: QuickTest[] = [
  {
    label: "Normal Request",
    description: "A clean request with no attack payload.",
    icon: ShieldQuestion,
    build: () => ({ method: "GET", path: BASE_PATH, queryParams: [], headers: [], body: "" }),
  },
  {
    label: "SQL Injection Test",
    description: "Tautology payload in a query parameter.",
    icon: Bug,
    build: () => ({
      method: "GET",
      path: BASE_PATH,
      queryParams: [newRow("id", "1' OR '1'='1")],
      headers: [],
      body: "",
    }),
  },
  {
    label: "XSS Test",
    description: "Script tag payload in a query parameter.",
    icon: SquareCode,
    build: () => ({
      method: "GET",
      path: BASE_PATH,
      queryParams: [newRow("q", "<script>alert(1)</script>")],
      headers: [],
      body: "",
    }),
  },
  {
    label: "Replay Attack Test",
    description: "Send twice with the same nonce - first 200, second 403.",
    icon: Repeat,
    build: () => ({
      method: "GET",
      path: BASE_PATH,
      queryParams: [],
      headers: [newRow("X-APIShield-Nonce", "demo-123")],
      body: "",
    }),
  },
];

interface QuickTestsProps {
  onSelect: (config: ApiRequestConfig) => void;
}

export function QuickTests({ onSelect }: QuickTestsProps) {
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {QUICK_TESTS.map(({ label, description, icon: Icon, build }) => (
        <button
          key={label}
          type="button"
          onClick={() => onSelect(build())}
          className="flex items-start gap-2.5 rounded-lg border border-border bg-surface-raised p-3 text-left transition-colors duration-150 hover:border-primary/30 hover:bg-surface-hover"
        >
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border bg-surface text-primary">
            <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
          </span>
          <span className="min-w-0">
            <span className="block text-xs font-medium text-text-primary">{label}</span>
            <span className="mt-0.5 block text-[11px] leading-snug text-text-muted">{description}</span>
          </span>
        </button>
      ))}
    </div>
  );
}
