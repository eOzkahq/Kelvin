import { useHealth } from "../hooks/useHealth";

export default function HomePage() {
  const { data, error, isPending, refetch, isFetching } = useHealth();

  return (
    <section aria-labelledby="status-heading" className="space-y-6">
      <div>
        <h1 id="status-heading" className="text-2xl font-semibold tracking-tight">
          Control plane status
        </h1>
        <p className="mt-1 text-sm text-zinc-400">
          Live liveness probe against <code className="text-zinc-300">GET /api/v1/health</code>.
        </p>
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
        {isPending && <p className="text-sm text-zinc-400">Checking control plane…</p>}

        {error instanceof Error && (
          <div className="space-y-2">
            <p className="text-sm font-medium text-red-400">Control plane unreachable</p>
            <p className="text-sm text-zinc-400">{error.message}</p>
            <p className="text-xs text-zinc-500">
              Start it with <code className="text-zinc-400">npm run dev:api</code> from the repository root.
            </p>
          </div>
        )}

        {data && (
          <dl className="grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Status</dt>
              <dd className="mt-1 font-medium text-emerald-400">{data.status}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">API version</dt>
              <dd className="mt-1 font-medium text-zinc-200">{data.apiVersion}</dd>
            </div>
          </dl>
        )}

        <button
          type="button"
          onClick={() => refetch()}
          disabled={isFetching}
          className="mt-4 rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
        >
          {isFetching ? "Refreshing…" : "Refresh"}
        </button>
      </div>
    </section>
  );
}
