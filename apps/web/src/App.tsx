import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage";
import { AppShell } from "./components/layout";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const FindingsWorkspacePage = lazy(() => import("./pages/FindingsWorkspacePage"));
const FindingDetailPage = lazy(() => import("./pages/FindingDetailPage"));
const AssessmentComparePage = lazy(() => import("./pages/AssessmentComparePage"));
const ReportCenterPage = lazy(() => import("./pages/ReportCenterPage"));
const AccountProfilePage = lazy(() => import("./pages/AccountProfilePage"));

export default function App() {
  return (
    <AppShell>
      <Suspense
        fallback={
          <div className="flex items-center justify-center py-16" role="status">
            <span className="text-xs text-zinc-400">Loading module…</span>
          </div>
        }
      >
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/findings" element={<FindingsWorkspacePage />} />
          <Route path="/compare" element={<AssessmentComparePage />} />
          <Route path="/reports" element={<ReportCenterPage />} />
          <Route path="*" element={<HomePage />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}
