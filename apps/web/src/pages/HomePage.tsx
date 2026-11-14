import { useHealth } from "../hooks/useHealth";
import { Button } from "../components/ui";

export default function HomePage() {
  const { data, error, isPending, refetch, isFetching } = useHealth();

  return (
    <section aria-labelledby="status-heading" className="space-y-6">
      <div>
        <h1 id="status-heading" className="text-2xl font-bold tracking-tight font-sans text-zinc-100">
          Control plane status
        </h1>
        <p className="mt-1 text-sm text-zinc-400 font-sans">
          Live liveness probe against <code className="text-[#d4c9a8] font-mono text-xs">GET /api/v1/health</code>.
        </p>
      </div>

      <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 p-5 backdrop-blur-xs">
        {isPending && <p className="text-sm text-zinc-400">Checking control plane…</p>}

        {error instanceof Error && (
          <div className="space-y-2">
            <p className="text-sm font-medium text-red-400">Control plane unreachable</p>
            <p className="text-sm text-zinc-400">{error.message}</p>
            <p className="text-xs text-zinc-500 font-mono">
              Start it with <code className="text-[#d4c9a8]">npm run dev:api</code> from the repository root.
            </p>
          </div>
        )}

        {data && (
          <dl className="grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase font-mono tracking-wider text-zinc-500">Status</dt>
              <dd className="mt-1 font-medium text-emerald-400 font-mono text-sm">{data.status}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase font-mono tracking-wider text-zinc-500">API version</dt>
              <dd className="mt-1 font-medium text-zinc-200 font-mono text-sm">{data.apiVersion}</dd>
            </div>
          </dl>
        )}

        <div className="mt-4">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            isLoading={isFetching}
          >
            {isFetching ? "Refreshing…" : "Refresh Probe"}
          </Button>
        </div>
      </div>
    </section>
  );
}
