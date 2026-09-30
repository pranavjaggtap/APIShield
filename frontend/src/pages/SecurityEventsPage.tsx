import { TopHeader } from "../components/layout/TopHeader";
import { SecurityEventsPanel } from "../components/api-console/SecurityEventsPanel";

export function SecurityEventsPage() {
  return (
    <div className="flex flex-1 flex-col">
      <TopHeader
        title="Security Events"
        description="Full audit trail of security decisions made by the gateway."
      />
      <main className="flex flex-1 flex-col gap-5 px-8 py-6">
        {/* Nothing on this page sends gateway requests, so there is no external refresh trigger;
            the panel's own Refresh button re-fetches. */}
        <SecurityEventsPanel refreshKey={0} />
      </main>
    </div>
  );
}
