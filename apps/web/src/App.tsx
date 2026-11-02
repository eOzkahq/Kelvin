import { lazy, Suspense } from "react";
import { Link, Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage";
import { useUI } from "./store/ui";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const FindingsWorkspacePage = lazy(() => import("./pages/FindingsWorkspacePage"));
const AssessmentComparePage = lazy(() => import("./pages/AssessmentComparePage"));
const ReportCenterPage = lazy(() => import("./pages/ReportCenterPage"));

export default function App() {
  const { sidebarOpen, toggleSidebar } = useUI();

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-6">
            <span className="text-lg font-semibold tracking-tight text-emerald-400">Kelvin</span>
            <nav className="flex gap-4 text-sm text-zinc-400" aria-label="Primary">
              <Link className="hover:text-zinc-100" to="/">
                Status
              </Link>
              <Link className="hover:text-zinc-100" to="/dashboard">
                Dashboard
              </Link>
              <Link className="hover:text-zinc-100" to="/findings">
                Findings
              </Link>
              <Link className="hover:text-zinc-100" to="/compare">
                Compare
              </Link>
              <Link className="hover:text-zinc-100" to="/reports">
                Reports
              </Link>
            </nav>
          </div>
          <button
            type="button"
            onClick={toggleSidebar}
            aria-expanded={sidebarOpen}
            className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:border-zinc-500"
          >
            {sidebarOpen ? "Hide" : "Show"} panel
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-8">
        <Suspense fallback={<p className="text-sm text-zinc-400">Loading…</p>}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/findings" element={<FindingsWorkspacePage />} />
            <Route path="/compare" element={<AssessmentComparePage />} />
            <Route path="/reports" element={<ReportCenterPage />} />
            <Route path="*" element={<HomePage />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}
