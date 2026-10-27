import { lazy, Suspense } from "react";
import { Link, Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage";
import { useUI } from "./store/ui";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));

export default function App() {
  const { sidebarOpen, toggleSidebar } = useUI();

  return (
    <div className="min-h-screen">
      <header className="border-b border-zinc-800">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-4">
            <span className="text-lg font-semibold tracking-tight text-emerald-400">Kelvin</span>
            <nav className="flex gap-3 text-sm text-zinc-400" aria-label="Primary">
              <Link className="hover:text-zinc-100" to="/">
                Status
              </Link>
              <Link className="hover:text-zinc-100" to="/dashboard">
                Dashboard
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

      <main className="mx-auto max-w-6xl px-4 py-8">
        <Suspense fallback={<p className="text-sm text-zinc-400">Loading…</p>}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="*" element={<HomePage />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}
