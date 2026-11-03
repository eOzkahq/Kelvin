import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage";
import LoginPage from "./pages/LoginPage";
import { AppShell } from "./components/layout";
import { ErrorBoundary } from "./components/ui";
import NotFoundPage from "./pages/error/NotFoundPage";
import ForbiddenPage from "./pages/error/ForbiddenPage";
import UnauthorizedPage from "./pages/error/UnauthorizedPage";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const FindingsWorkspacePage = lazy(() => import("./pages/FindingsWorkspacePage"));
const FindingDetailPage = lazy(() => import("./pages/FindingDetailPage"));
const RemediationWorkspacePage = lazy(() => import("./pages/RemediationWorkspacePage"));
const TargetsManagementPage = lazy(() => import("./pages/TargetsManagementPage"));
const OrgAdminPage = lazy(() => import("./pages/OrgAdminPage"));
const TeamMembersPage = lazy(() => import("./pages/TeamMembersPage"));
const RolesPermissionsSsoPage = lazy(() => import("./pages/RolesPermissionsSsoPage"));
const IntegrationsNotificationPage = lazy(() => import("./pages/IntegrationsNotificationPage"));
const AuditLogsPage = lazy(() => import("./pages/AuditLogsPage"));
const PlatformSettingsPage = lazy(() => import("./pages/PlatformSettingsPage"));
const AssessmentComparePage = lazy(() => import("./pages/AssessmentComparePage"));
const ReportCenterPage = lazy(() => import("./pages/ReportCenterPage"));
const AccountProfilePage = lazy(() => import("./pages/AccountProfilePage"));
const AssessmentListPage = lazy(() => import("./pages/AssessmentListPage"));
const AssessmentWizardPage = lazy(() => import("./pages/AssessmentWizardPage"));
const AssessmentDetailPage = lazy(() => import("./pages/AssessmentDetailPage"));

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
        <Route path="/unauthorized" element={<UnauthorizedPage />} />
        <Route path="/forbidden" element={<ForbiddenPage />} />
        <Route
          path="/*"
          element={
            <AppShell>
              <ErrorBoundary>
                <Routes>
                  <Route path="/" element={<HomePage />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/assessments" element={<AssessmentListPage />} />
                  <Route path="/assessments/new" element={<AssessmentWizardPage />} />
                  <Route path="/assessments/:id" element={<AssessmentDetailPage />} />
                  <Route path="/findings" element={<FindingsWorkspacePage />} />
                  <Route path="/findings/:id" element={<FindingDetailPage />} />
                  <Route path="/remediation" element={<RemediationWorkspacePage />} />
                  <Route path="/targets" element={<TargetsManagementPage />} />
                  <Route path="/admin/org" element={<OrgAdminPage />} />
                  <Route path="/admin/team" element={<TeamMembersPage />} />
                  <Route path="/admin/roles" element={<RolesPermissionsSsoPage />} />
                  <Route path="/admin/integrations" element={<IntegrationsNotificationPage />} />
                  <Route path="/admin/settings" element={<PlatformSettingsPage />} />
                  <Route path="/audit" element={<AuditLogsPage />} />
                  <Route path="/compare" element={<AssessmentComparePage />} />
                  <Route path="/reports" element={<ReportCenterPage />} />
                  <Route path="/profile" element={<AccountProfilePage />} />
                  <Route path="*" element={<NotFoundPage />} />
                </Routes>
              </ErrorBoundary>
            </AppShell>
          }
        />
      </Routes>
    </Suspense>
  );
}
