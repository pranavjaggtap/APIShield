import type { LucideIcon } from "lucide-react";
import { Construction } from "lucide-react";

interface PlaceholderPageProps {
  icon: LucideIcon;
  title: string;
  description: string;
}

/**
 * Used by every navigation destination that isn't wired to real functionality
 * yet (Threats, Requests, Security Events, Analytics, Settings). Deliberately
 * does not fabricate data or fake interactivity - it honestly communicates
 * that the capability is part of the APIShield platform and will be connected
 * as backend implementation progresses.
 */
export function PlaceholderPage({ icon: Icon, title, description }: PlaceholderPageProps) {
  return (
    <div className="flex flex-1 items-center justify-center px-8 py-16">
      <div className="flex max-w-md flex-col items-center text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-border bg-surface">
          <Icon className="h-6 w-6 text-primary" strokeWidth={1.75} />
        </div>
        <h2 className="mt-5 text-lg font-semibold text-text-primary">{title}</h2>
        <p className="mt-2 text-sm leading-relaxed text-text-secondary">{description}</p>
        <div className="mt-5 inline-flex items-center gap-1.5 rounded-full border border-border-strong bg-surface-raised px-3 py-1 text-xs font-medium text-text-muted">
          <Construction className="h-3.5 w-3.5" />
          In development
        </div>
      </div>
    </div>
  );
}
