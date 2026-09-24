import { Settings } from "lucide-react";
import { TopHeader } from "../components/layout/TopHeader";
import { PlaceholderPage } from "../components/common/PlaceholderPage";

export function SettingsPage() {
  return (
    <div className="flex flex-1 flex-col">
      <TopHeader title="Settings" description="Configure detectors, thresholds and platform preferences." />
      <PlaceholderPage
        icon={Settings}
        title="Platform settings"
        description="Detector thresholds, decision policy configuration and notification preferences will live here. No authentication is implemented yet, so this section is read-only."
      />
    </div>
  );
}
