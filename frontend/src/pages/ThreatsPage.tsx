import { ShieldAlert } from "lucide-react";
import { TopHeader } from "../components/layout/TopHeader";
import { PlaceholderPage } from "../components/common/PlaceholderPage";

export function ThreatsPage() {
  return (
    <div className="flex flex-1 flex-col">
      <TopHeader
        title="Threats"
        description="Detailed view of SQL injection, XSS, replay, frequency abuse and bot automation detections."
      />
      <PlaceholderPage
        icon={ShieldAlert}
        title="Detailed threat explorer"
        description="A filterable, drill-down view of every threat detected by APIShield's security pipeline will live here as the dashboard backend is connected."
      />
    </div>
  );
}
