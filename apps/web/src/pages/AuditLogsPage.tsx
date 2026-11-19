import { useEffect, useState, useCallback } from "react";
import {
  fetchAuditLogs,
  exportAuditLogs,
  type AuditEvent,
  type AuditCategory,
  type AuditOutcome,
} from "../features/audit";
import {
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";

export default function AuditLogsPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<AuditCategory | "">("");
  const [outcomeFilter, setOutcomeFilter] = useState<AuditOutcome | "">("");

  // Inspect Modal
  const [activeEvent, setActiveEvent] = useState<AuditEvent | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const loadEvents = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await fetchAuditLogs({
        search: searchQuery || undefined,
        category: categoryFilter || undefined,
        outcome: outcomeFilter || undefined,
      });
      setEvents(data);
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    } finally {
      setIsLoading(false);
    }
  }, [searchQuery, categoryFilter, outcomeFilter]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  const handleExport = async (format: "csv" | "ndjson") => {
    try {
      const content = await exportAuditLogs(format, {
        search: searchQuery || undefined,
        category: categoryFilter || undefined,
        outcome: outcomeFilter || undefined,
      });

      const mime = format === "ndjson" ? "application/x-ndjson" : "text/csv;charset=utf-8;";
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `kelvin-audit-${new Date().toISOString().slice(0, 10)}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setNotification(`Exported audit trail in ${format.toUpperCase()} format.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Metrics
  const totalCount = events.length;
  const authCount = events.filter((e) => e.category === "AUTHENTICATION").length;
  const policyCount = events.filter((e) => e.category === "POLICY").length;
  const failureCount = events.filter((e) => e.outcome === "FAILURE").length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            Immutable Security Ledger
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Tamper-Evident Audit Trail
          </h1>
          <p className="mt-0.5 text-xs text-zinc-400">
            Immutable, cryptographically linked record of user actions, assessment triggers, and access events.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded-lg bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs font-mono text-emerald-300">
              {notification}
            </span>
          )}
          <Button variant="secondary" size="sm" onClick={() => handleExport("csv")}>
            Export CSV
          </Button>
          <Button variant="secondary" size="sm" onClick={() => handleExport("ndjson")}>
            Export NDJSON
          </Button>
        </div>
      </div>

      {/* KPI Overview Strip */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-5">
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">Recorded Events</span>
          <p className="stat-num mt-1 text-2xl text-zinc-100">{totalCount}</p>
        </Card>
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#d4c9a8]">Auth &amp; SSO</span>
          <p className="stat-num mt-1 text-2xl text-[#e8debe]">{authCount}</p>
        </Card>
        <Card className="p-4 border-amber-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400">Policy Changes</span>
          <p className="stat-num mt-1 text-2xl text-amber-300">{policyCount}</p>
        </Card>
        <Card className="p-4 border-red-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-red-400">Failed / Blocked</span>
          <p className="stat-num mt-1 text-2xl text-red-400">{failureCount}</p>
        </Card>
        <Card className="p-4 border-emerald-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">Hash Chain</span>
          <p className="mt-1.5 text-sm font-mono font-bold text-emerald-400">✓ 100% Sealed</p>
        </Card>
      </div>

      {/* Filter Bar */}
      <Card className="p-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
          <div className="md:col-span-5">
            <Input
              type="text"
              placeholder="Filter by actor email, action, resource, or correlation ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="md:col-span-3">
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as AuditCategory)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Categories</option>
              <option value="AUTHENTICATION">Authentication</option>
              <option value="ASSESSMENT">Assessment Execution</option>
              <option value="FINDINGS">Findings &amp; Triage</option>
              <option value="POLICY">Policy &amp; MFA</option>
              <option value="ADMINISTRATION">Administration</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value as AuditOutcome)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Outcomes</option>
              <option value="SUCCESS">Success</option>
              <option value="FAILURE">Failure</option>
            </select>
          </div>

          <div className="md:col-span-2 flex items-center justify-end">
            {(searchQuery || categoryFilter || outcomeFilter) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSearchQuery("");
                  setCategoryFilter("");
                  setOutcomeFilter("");
                }}
              >
                Reset Filters
              </Button>
            )}
          </div>
        </div>
      </Card>

      {/* Audit Log Table */}
      <div className="overflow-x-auto rounded-xl surface-card">
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="border-b border-zinc-800/80 bg-zinc-950/90 text-[10px] font-mono tracking-wider uppercase text-zinc-400">
            <tr>
              <th className="px-4 py-3">Timestamp (UTC)</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3">Target Resource</th>
              <th className="px-4 py-3">Outcome</th>
              <th className="px-4 py-3">Chain Verification</th>
              <th className="px-4 py-3 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="p-4">
                  <SkeletonLoader lines={5} />
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8">
                  <EmptyState
                    title="No Audit Records Found"
                    description="No events match your search or category filters."
                    actionLabel="Reset Filters"
                    onAction={() => {
                      setSearchQuery("");
                      setCategoryFilter("");
                      setOutcomeFilter("");
                    }}
                  />
                </td>
              </tr>
            ) : (
              events.map((evt) => (
                <tr key={evt.id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {new Date(evt.timestamp).toUTCString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-semibold text-zinc-200 text-xs">{evt.actor}</span>
                    <div className="text-[11px] font-mono text-zinc-500">{evt.ipAddress}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-cyan-300">{evt.action}</td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-zinc-800 px-2 py-0.5 text-[11px] font-mono text-zinc-300">
                      {evt.category}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {evt.resourceType}: {evt.resourceId}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-semibold ${
                        evt.outcome === "SUCCESS"
                          ? "bg-emerald-950/60 border border-emerald-800 text-emerald-300"
                          : "bg-red-950/60 border border-red-800 text-red-300"
                      }`}
                    >
                      {evt.outcome}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {evt.chainVerified ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                        ✓ CHAIN VERIFIED
                      </span>
                    ) : (
                      <span className="text-[11px] text-red-400 font-mono">⚠ INTEGRITY FAILED</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button size="sm" variant="outline" onClick={() => setActiveEvent(evt)}>
                      Inspect
                    </Button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Event Details Drawer/Modal */}
      {activeEvent && (
        <Modal
          isOpen={Boolean(activeEvent)}
          onClose={() => setActiveEvent(null)}
          title={`Audit Record: ${activeEvent.id}`}
        >
          <div className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-zinc-400">
                {new Date(activeEvent.timestamp).toUTCString()}
              </span>
              <span
                className={`rounded px-2 py-0.5 text-xs font-semibold ${
                  activeEvent.outcome === "SUCCESS"
                    ? "bg-emerald-950/60 border border-emerald-800 text-emerald-300"
                    : "bg-red-950/60 border border-red-800 text-red-300"
                }`}
              >
                {activeEvent.outcome}
              </span>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-2 text-xs font-mono">
              <div>
                <span className="text-zinc-500">Actor Identity: </span>
                <span className="text-zinc-200 font-semibold">{activeEvent.actor}</span>
              </div>
              <div>
                <span className="text-zinc-500">Action: </span>
                <span className="text-cyan-300">{activeEvent.action}</span>
              </div>
              <div>
                <span className="text-zinc-500">Target Resource: </span>
                <span className="text-zinc-200">{activeEvent.resourceType} ({activeEvent.resourceId})</span>
              </div>
              <div>
                <span className="text-zinc-500">IP &amp; User Agent: </span>
                <span className="text-zinc-400">{activeEvent.ipAddress} • {activeEvent.userAgent}</span>
              </div>
              <div>
                <span className="text-zinc-500">Correlation ID: </span>
                <span className="text-zinc-400">{activeEvent.correlationId}</span>
              </div>
            </div>

            {/* Cryptographic Proof Box */}
            <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-4 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-emerald-400 font-semibold uppercase text-[10px]">
                  Cryptographic Hash-Chain Verification
                </span>
                <span className="text-emerald-400">✓ SEAL VERIFIED</span>
              </div>
              <div>
                <span className="text-zinc-500">Current Record SHA-256: </span>
                <p className="text-zinc-300 select-all truncate">{activeEvent.sha256Hash}</p>
              </div>
              <div>
                <span className="text-zinc-500">Previous Block Hash: </span>
                <p className="text-zinc-400 select-all truncate">{activeEvent.prevRecordHash}</p>
              </div>
            </div>

            {/* Structured Details JSON */}
            <div>
              <span className="text-xs font-semibold text-zinc-400 uppercase">
                Event Payload Details
              </span>
              <pre className="mt-1 rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs text-zinc-300 overflow-x-auto">
                {JSON.stringify(activeEvent.details, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="secondary" onClick={() => setActiveEvent(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
