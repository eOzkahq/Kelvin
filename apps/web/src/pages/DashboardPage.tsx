export default function DashboardPage() {
  return (
    <section aria-labelledby="dashboard-heading" className="space-y-4">
      <div>
        <h1 id="dashboard-heading" className="text-2xl font-semibold tracking-tight">
          Dashboard
        </h1>
        <p className="mt-1 text-sm text-zinc-400">
          Role-scoped views (PERSONAS §5.1) arrive with the design-system milestone.
        </p>
      </div>

      <div
        className="rounded-lg border border-dashed border-zinc-700 bg-zinc-900/40 p-6"
        data-placeholder="dashboard-shell"
      >
        <p className="text-sm text-zinc-300">This page is an intentionally empty shell.</p>
        <p className="mt-2 text-sm text-zinc-500">
          It performs no API calls, renders no mock data, and contains no authorization logic —
          client-side permissions are cosmetic only (RBAC_MATRIX §10); enforcement is server-side.
        </p>
      </div>
    </section>
  );
}
