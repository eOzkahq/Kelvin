import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage";
import { AppShell } from "./components/layout";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const AssessmentListPage = lazy(() => import("./pages/AssessmentListPage"));
const AssessmentWizardPage = lazy(() => import("./pages/AssessmentWizardPage"));
const AssessmentDetailPage = lazy(() => import("./pages/AssessmentDetailPage"));
const FindingsWorkspacePage = lazy(() => import("./pages/FindingsWorkspacePage"));
const FindingDetailPage = lazy(() => import("./pages/FindingDetailPage"));
const RemediationWorkspacePage = lazy(() => import("./pages/RemediationWorkspacePage"));
const TargetsManagementPage = lazy(() => import("./pages/TargetsManagementPage"));
const AssessmentComparePage = lazy(() => import("./pages/AssessmentComparePage"));
const ReportCenterPage = lazy(() => import("./pages/ReportCenterPage"));
const AuditLogsPage = lazy(() => import("./pages/AuditLogsPage"));
const AccountProfilePage = lazy(() => import("./pages/AccountProfilePage"));
const OrgAdminPage = lazy(() => import("./pages/OrgAdminPage"));
const TeamMembersPage = lazy(() => import("./pages/TeamMembersPage"));
const RolesPermissionsSsoPage = lazy(() => import("./pages/RolesPermissionsSsoPage"));
const IntegrationsNotificationPage = lazy(() => import("./pages/IntegrationsNotificationPage"));
const PlatformSettingsPage = lazy(() => import("./pages/PlatformSettingsPage"));

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
          <Route path="/assessments" element={<AssessmentListPage />} />
          <Route path="/assessments/new" element={<AssessmentWizardPage />} />
          <Route path="/assessments/:id" element={<AssessmentDetailPage />} />
          <Route path="/findings" element={<FindingsWorkspacePage />} />
          <Route path="/findings/:id" element={<FindingDetailPage />} />
          <Route path="/remediation" element={<RemediationWorkspacePage />} />
          <Route path="/targets" element={<TargetsManagementPage />} />
          <Route path="/compare" element={<AssessmentComparePage />} />
          <Route path="/reports" element={<ReportCenterPage />} />
          <Route path="/audit" element={<AuditLogsPage />} />
          <Route path="/account" element={<AccountProfilePage />} />
          <Route path="/profile" element={<AccountProfilePage />} />
          <Route path="/settings" element={<PlatformSettingsPage />} />
          <Route path="/admin/org" element={<OrgAdminPage />} />
          <Route path="/admin/team" element={<TeamMembersPage />} />
          <Route path="/admin/roles" element={<RolesPermissionsSsoPage />} />
          <Route path="/admin/integrations" element={<IntegrationsNotificationPage />} />
          <Route path="/admin/settings" element={<PlatformSettingsPage />} />
          <Route path="*" element={<HomePage />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}
