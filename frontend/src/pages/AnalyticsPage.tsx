import { BarChart3 } from "lucide-react";
import { TopHeader } from "../components/layout/TopHeader";
import { PlaceholderPage } from "../components/common/PlaceholderPage";

export function AnalyticsPage() {
  return (
    <div className="flex flex-1 flex-col">
      <TopHeader title="Analytics" description="Longer-term trends across traffic, risk and threat activity." />
      <PlaceholderPage
        icon={BarChart3}
        title="Extended analytics"
        description="Deeper historical analysis - trend comparisons, per-endpoint risk breakdowns and detector effectiveness - will live here as more telemetry is collected."
      />
    </div>
  );
}
