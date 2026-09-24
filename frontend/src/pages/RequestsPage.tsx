import { Network } from "lucide-react";
import { TopHeader } from "../components/layout/TopHeader";
import { PlaceholderPage } from "../components/common/PlaceholderPage";

export function RequestsPage() {
  return (
    <div className="flex flex-1 flex-col">
      <TopHeader title="Requests" description="Inspect individual API requests as they pass through the gateway." />
      <PlaceholderPage
        icon={Network}
        title="Request inspector"
        description="A searchable log of individual gateway requests - method, path, client, decision and evaluation timing - will live here once request-level persistence is implemented."
      />
    </div>
  );
}
