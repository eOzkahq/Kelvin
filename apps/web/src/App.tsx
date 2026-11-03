import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage";
import LoginPage from "./pages/LoginPage";
import { AppShell } from "./components/layout";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const FindingsWorkspacePage = lazy(() => import("./pages/FindingsWorkspacePage"));
const AssessmentComparePage = lazy(() => import("./pages/AssessmentComparePage"));
const ReportCenterPage = lazy(() => import("./pages/ReportCenterPage"));
const AccountProfilePage = lazy(() => import("./pages/AccountProfilePage"));
const AssessmentListPage = lazy(() => import("./pages/AssessmentListPage"));
const AssessmentWizardPage = lazy(() => import("./pages/AssessmentWizardPage"));

export default function App() {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-screen items-center justify-center bg-zinc-950 text-xs text-zinc-500">
          Loading module…
        </div>
      }
    >
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <AppShell>
              <Routes>
                <Route path="/" element={<HomePage />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/assessments" element={<AssessmentListPage />} />
                <Route path="/assessments/new" element={<AssessmentWizardPage />} />
                <Route path="/findings" element={<FindingsWorkspacePage />} />
                <Route path="/compare" element={<AssessmentComparePage />} />
                <Route path="/reports" element={<ReportCenterPage />} />
                <Route path="/profile" element={<AccountProfilePage />} />
                <Route path="*" element={<HomePage />} />
              </Routes>
            </AppShell>
          }
        />
      </Routes>
    </Suspense>
  );
}
