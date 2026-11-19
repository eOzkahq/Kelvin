import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./features/auth/AuthContext";
import { PlanProvider } from "./features/billing/PlanContext";
import { PaywallModal } from "./components/billing/PaywallModal";
import { ProtectedRoute } from "./features/auth/ProtectedRoute";
import LoginPage from "./pages/LoginPage";
import { AppShell } from "./components/layout";
import { ErrorBoundary } from "./components/ui/ErrorBoundary";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const OnboardingPage = lazy(() => import("./pages/OnboardingPage"));
const PlansBillingPage = lazy(() => import("./pages/PlansBillingPage"));
const CheckoutPage = lazy(() => import("./pages/CheckoutPage"));
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

const LOADER = (
  <div className="flex h-screen items-center justify-center bg-zinc-950" role="status">
    <span className="text-xs text-zinc-400">Loading…</span>
  </div>
);

function SessionExpiredBanner() {
  const { sessionExpired, dismissSessionExpired, logout } = useAuth();
  if (!sessionExpired) return null;

  return (
    <div className="fixed inset-x-0 top-0 z-[9999] flex items-center justify-between bg-amber-900/95 px-4 py-2 text-xs text-amber-100 border-b border-amber-700">
      <span>⚠️ Your session has expired. Please sign in again.</span>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={dismissSessionExpired}
          className="text-amber-300 hover:text-amber-100 underline"
        >
          Dismiss
        </button>
        <button
          type="button"
          onClick={() => { void logout(); }}
          className="rounded bg-amber-700 px-2 py-0.5 hover:bg-amber-600 font-medium"
        >
          Sign in
        </button>
      </div>
    </div>
  );
}

function AppRoutes() {
  return (
    <ErrorBoundary fallbackTitle="Application Error">
      <Suspense fallback={LOADER}>
        <Routes>
          {/* Public */}
          <Route path="/login" element={<LoginPage />} />

          {/* Catch-all: redirect / to /dashboard */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />

          {/* All protected routes wrapped in AppShell */}
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <AppShell>
                  <ErrorBoundary fallbackTitle="Module Rendering Error">
                    <Suspense fallback={<div className="py-16 text-center text-xs text-zinc-400">Loading module…</div>}>
                      <Routes>
                        <Route path="/dashboard" element={<DashboardPage />} />
                        <Route path="/onboarding" element={<OnboardingPage />} />
                        <Route path="/plans" element={<PlansBillingPage />} />
                        <Route path="/checkout" element={<CheckoutPage />} />
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
                        <Route path="/admin" element={<OrgAdminPage />} />
                        <Route path="/admin/org" element={<OrgAdminPage />} />
                        <Route path="/team" element={<TeamMembersPage />} />
                        <Route path="/admin/team" element={<TeamMembersPage />} />
                        <Route path="/roles" element={<RolesPermissionsSsoPage />} />
                        <Route path="/admin/roles" element={<RolesPermissionsSsoPage />} />
                        <Route path="/integrations" element={<IntegrationsNotificationPage />} />
                        <Route path="/admin/integrations" element={<IntegrationsNotificationPage />} />
                        <Route path="/settings" element={<PlatformSettingsPage />} />
                        <Route path="/admin/settings" element={<PlatformSettingsPage />} />
                        {/* Unknown sub-routes → dashboard */}
                        <Route path="*" element={<Navigate to="/dashboard" replace />} />
                      </Routes>
                    </Suspense>
                  </ErrorBoundary>
                </AppShell>
              </ProtectedRoute>
            }
          />
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <PlanProvider>
        <SessionExpiredBanner />
        <PaywallModal />
        <AppRoutes />
      </PlanProvider>
    </AuthProvider>
  );
}
