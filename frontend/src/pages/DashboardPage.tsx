import { useDashboardData } from "../hooks/useDashboardData";
import { TopHeader } from "../components/layout/TopHeader";
import { DashboardHeaderControls } from "../components/dashboard/DashboardHeaderControls";
import { SecurityPostureCard } from "../components/dashboard/SecurityPostureCard";
import { KpiGrid } from "../components/dashboard/KpiGrid";
import { TrafficChart } from "../components/charts/TrafficChart";
import { ThreatDistributionChart } from "../components/charts/ThreatDistributionChart";
import { RiskTrendChart } from "../components/charts/RiskTrendChart";
import { DecisionDistribution } from "../components/dashboard/DecisionDistribution";
import { RecentEventsTable } from "../components/dashboard/RecentEventsTable";
import { LiveActivityFeed } from "../components/dashboard/LiveActivityFeed";
import { SystemHealthPanel } from "../components/dashboard/SystemHealthPanel";
import { Card } from "../components/common/Card";
import { LoadingPanel } from "../components/common/LoadingState";
import { ErrorState } from "../components/common/ErrorState";

export function DashboardPage() {
  const { data, loading, error, refresh } = useDashboardData();

  if (!data && loading) {
    return (
      <div className="flex flex-1 flex-col">
        <TopHeader title="Security Overview" description="Monitor API traffic, threats, risk scores and security decisions." />
        <div className="flex flex-1 items-center justify-center">
          <LoadingPanel />
        </div>
      </div>
    );
  }

  if (!data && error) {
    return (
      <div className="flex flex-1 flex-col">
        <TopHeader title="Security Overview" description="Monitor API traffic, threats, risk scores and security decisions." />
        <div className="flex flex-1 items-center justify-center">
          <ErrorState message={error} onRetry={refresh} />
        </div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="flex flex-1 flex-col">
      <TopHeader title="Security Overview" description="Monitor API traffic, threats, risk scores and security decisions.">
        <DashboardHeaderControls health={data.health} loading={loading} onRefresh={refresh} />
      </TopHeader>

      <main className="flex flex-1 flex-col gap-5 px-8 py-6">
        <SecurityPostureCard summary={data.summary} />

        <KpiGrid summary={data.summary} />

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <Card
            title="Request Traffic"
            description="Allowed, monitored and blocked requests over the last 24 hours"
            className="xl:col-span-2"
          >
            <TrafficChart data={data.traffic} />
          </Card>
          <Card title="Threat Distribution" description="Detections by threat type">
            <ThreatDistributionChart data={data.threats} />
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <Card
            title="Risk Trend"
            description="Average API risk score over time, relative to the block threshold"
            className="xl:col-span-2"
          >
            <RiskTrendChart data={data.risk} />
          </Card>
          <Card title="Decision Distribution" description="Gateway decisions on evaluated requests">
            <DecisionDistribution data={data.decisions} />
          </Card>
        </div>

        <Card
          title="Recent Security Events"
          description="Most recent requests evaluated by the security pipeline"
          bodyClassName="p-0"
        >
          <RecentEventsTable events={data.events} />
        </Card>

        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <Card title="Live Activity Feed" description="Real-time stream of security decisions" className="xl:col-span-2">
            <LiveActivityFeed events={data.events.slice(0, 6)} />
          </Card>
          <Card title="System Health" description="Core APIShield infrastructure">
            <SystemHealthPanel health={data.health} />
          </Card>
        </div>
      </main>
    </div>
  );
}
