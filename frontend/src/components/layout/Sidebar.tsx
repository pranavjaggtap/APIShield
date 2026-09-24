import {
  BarChart3,
  FileWarning,
  LayoutDashboard,
  Network,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UserCog,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { cn } from "../../lib/cn";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/api-console", label: "API Console", icon: Terminal, end: false },
  { to: "/threats", label: "Threats", icon: ShieldAlert, end: false },
  { to: "/requests", label: "Requests", icon: Network, end: false },
  { to: "/security-events", label: "Security Events", icon: FileWarning, end: false },
  { to: "/analytics", label: "Analytics", icon: BarChart3, end: false },
  { to: "/settings", label: "Settings", icon: Settings, end: false },
];

export function Sidebar() {
  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-border bg-surface">
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-5">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/25 bg-primary/10">
          <ShieldCheck className="h-5 w-5 text-primary" strokeWidth={2} />
        </span>
        <div>
          <p className="text-sm font-semibold leading-tight text-text-primary">APIShield</p>
          <p className="text-[11px] leading-tight text-text-muted">Intelligent API Security</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4" aria-label="Primary">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors duration-150",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-text-secondary hover:bg-surface-hover hover:text-text-primary",
              )
            }
          >
            <Icon className="h-4 w-4" strokeWidth={1.75} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border px-3 py-4">
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-border bg-surface-raised px-3 py-2">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success/50" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-success" />
          </span>
          <span className="text-xs font-medium text-text-secondary">Local Demo Environment</span>
        </div>

        <div className="flex items-center gap-2.5 rounded-lg px-3 py-2">
          <span className="flex h-8 w-8 items-center justify-center rounded-full border border-border bg-surface-raised">
            <UserCog className="h-4 w-4 text-text-muted" strokeWidth={1.75} />
          </span>
          <div className="min-w-0">
            <p className="truncate text-xs font-medium text-text-primary">Security Admin</p>
            <p className="truncate text-[11px] text-text-muted">No authentication configured</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
