# APIShield Frontend

The dashboard MVP for **APIShield — Intelligent API Security**, a Spring Cloud
Gateway-based security gateway. This frontend is a standalone Vite + React +
TypeScript application that visualizes gateway security posture, traffic,
threats, risk scoring, and decisions.

## Status

This is a **visualization MVP running entirely on mock data**. The Dashboard
page is fully functional against fixtures in `src/data/mockData.ts`. No
backend dashboard API exists yet - see "Backend integration" below. The other
navigation destinations (Threats, Requests, Security Events, Analytics,
Settings) are polished placeholder pages, not implemented functionality.

## Stack

React 19, TypeScript, Vite, Tailwind CSS v4 (via `@tailwindcss/vite`),
Recharts, Lucide React, React Router, clsx + tailwind-merge.

## Running

```bash
npm install
npm run dev       # http://localhost:5173, mock data, no backend required
npm run build      # production build to dist/
npm run preview    # preview the production build
```

Fully independent of the Java backend - it only ever talks to the mock
`DashboardService` implementation.

## Architecture

- `types/dashboard.ts` — the full data model (`DashboardSummary`,
  `SecurityEvent`, `ThreatStatistic`, `TrafficPoint`, `RiskPoint`,
  `DecisionStatistic`, `SystemHealth`).
- `data/mockData.ts` — hand-authored/deterministically generated fixtures.
  **Not real telemetry** - clearly labeled as such in the file itself.
- `services/dashboardService.ts` — the `DashboardService` interface every data
  source (mock or real) must satisfy, plus `getDashboardService()`, the single
  swap point used everywhere in the UI.
- `services/mockDashboardService.ts` — the current implementation, with
  simulated network latency so loading states are genuinely exercised.
- `hooks/useDashboardData.ts` — fetches all dashboard data through the service
  abstraction and exposes `{ data, loading, error, refresh }`.
- `components/` — `layout/` (shell, sidebar, header), `dashboard/`
  (posture, KPIs, tables, feed), `charts/` (Recharts wrappers with the
  dashboard's dark theme), `security/` (threat/decision/severity badges),
  `common/` (Card, Badge, empty/loading/error states).

## Backend integration (future work, not implemented here)

Planned backend routes, matching the types above field-for-field:

```
GET /api/dashboard/summary
GET /api/dashboard/threats
GET /api/dashboard/events
GET /api/dashboard/traffic
GET /api/dashboard/risk
GET /api/dashboard/health
```

To connect a real backend: implement `services/apiDashboardService.ts`
against the `DashboardService` interface using `fetch`, then change
`getDashboardService()` to return it. No UI component needs to change.

`vite.config.ts` already proxies `/api/*` to `http://localhost:8080` in dev,
so once those endpoints exist, calls are same-origin from the browser's
perspective and no backend CORS configuration is required for local
development.

## Known frontend/backend discrepancy

The Decision Distribution visualization includes a `MONITOR` state alongside
`ALLOW`/`BLOCK`. The current backend `DecisionEngine`
(`com.apishield.decision.DefaultDecisionEngine`) only supports `ALLOW` and
`BLOCK` - `MONITOR` is included here as anticipated future capability, and is
called out as such directly in the UI (`DecisionDistribution.tsx`) and in the
`types/dashboard.ts` doc comment.
