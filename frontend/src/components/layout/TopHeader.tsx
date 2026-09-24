import type { ReactNode } from "react";

interface TopHeaderProps {
  title: string;
  description: string;
  children?: ReactNode;
}

/**
 * Generic page header used by every route - title, description, and an
 * optional right-side control slot. The dashboard populates that slot with
 * live status indicators / time-range / refresh; placeholder pages leave it
 * empty rather than showing controls that don't do anything yet.
 */
export function TopHeader({ title, description, children }: TopHeaderProps) {
  return (
    <header className="flex flex-col gap-4 border-b border-border bg-background/95 px-8 py-5 backdrop-blur supports-[backdrop-filter]:bg-background/80 lg:flex-row lg:items-center lg:justify-between">
      <div>
        <h1 className="text-lg font-semibold text-text-primary">{title}</h1>
        <p className="mt-0.5 text-sm text-text-secondary">{description}</p>
      </div>
      {children && <div className="flex flex-wrap items-center gap-4">{children}</div>}
    </header>
  );
}
