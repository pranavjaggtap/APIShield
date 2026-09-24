import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";

/** The persistent application frame - sidebar plus the routed page content. */
export function AppShell() {
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col overflow-y-auto">
        <Outlet />
      </div>
    </div>
  );
}
