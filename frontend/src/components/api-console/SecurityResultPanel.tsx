import { ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react";
import type { SecurityInference } from "../../types/apiConsole";
import { cn } from "../../lib/cn";

interface SecurityResultPanelProps {
  inference: SecurityInference | null;
}

const INFERENCE_META: Record<
  SecurityInference,
  { label: string; icon: typeof ShieldCheck; color: string; badgeBg: string; explanation: string }
> = {
  BLOCKED: {
    label: "Blocked",
    icon: ShieldX,
    color: "text-danger",
    badgeBg: "bg-danger/10 border-danger/25",
    explanation: "APIShield returned HTTP 403 with its security block response - the security pipeline stopped this request before it reached User Service.",
  },
  NOT_BLOCKED: {
    label: "Not Blocked",
    icon: ShieldCheck,
    color: "text-success",
    badgeBg: "bg-success/10 border-success/25",
    explanation: "APIShield did not return its security block response. The status above reflects what the gateway or downstream service actually returned.",
  },
  UNKNOWN: {
    label: "Unknown",
    icon: ShieldQuestion,
    color: "text-text-muted",
    badgeBg: "bg-white/5 border-border-strong",
    explanation: "No response was received, so no security outcome could be determined.",
  },
};

export function SecurityResultPanel({ inference }: SecurityResultPanelProps) {
  if (!inference) {
    return (
      <div className="flex min-h-[140px] items-center justify-center text-center text-sm text-text-muted">
        Send a request to see the security result here.
      </div>
    );
  }

  const meta = INFERENCE_META[inference];
  const Icon = meta.icon;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <span className={cn("flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border", meta.badgeBg)}>
          <Icon className={cn("h-5 w-5", meta.color)} strokeWidth={1.75} />
        </span>
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-text-muted">Request Result</p>
          <p className={cn("text-lg font-semibold tracking-tight", meta.color)}>{meta.label.toUpperCase()}</p>
        </div>
      </div>

      <p className="text-sm leading-relaxed text-text-secondary">{meta.explanation}</p>

      <p className="border-t border-border pt-3 text-[11px] leading-relaxed text-text-muted">
        This result is inferred from the HTTP response alone. The full decision - risk score, threat score and every
        detector&apos;s signal - is recorded by APIShield and shown in the Security Events panel below.
      </p>
    </div>
  );
}
