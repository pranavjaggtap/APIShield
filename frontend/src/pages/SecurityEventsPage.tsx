import { FileWarning } from "lucide-react";
import { TopHeader } from "../components/layout/TopHeader";
import { PlaceholderPage } from "../components/common/PlaceholderPage";

export function SecurityEventsPage() {
  return (
    <div className="flex flex-1 flex-col">
      <TopHeader
        title="Security Events"
        description="Full audit trail of security decisions made by the gateway."
      />
      <PlaceholderPage
        icon={FileWarning}
        title="Security event log"
        description="A complete, filterable audit trail backed by PostgreSQL-persisted security events will live here once event persistence is implemented on the backend."
      />
    </div>
  );
}
