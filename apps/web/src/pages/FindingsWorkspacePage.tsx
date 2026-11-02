import { useEffect, useState } from "react";
import {
  type DashboardMetrics,
  type EvidenceItem,
  type Finding,
  type FindingObservation,
  fetchDashboardMetrics,
  fetchFindingEvidence,
  fetchFindingObservations,
  fetchFindings,
  transitionFinding,
} from "../services/findingsApi";

export default function FindingsWorkspacePage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("");
  const [selectedStatus, setSelectedStatus] = useState("");
  const [selectedScanner, setSelectedScanner] = useState("");

  // Drawer detail state
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);
  const [observations, setObservations] = useState<FindingObservation[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [triageStatus, setTriageStatus] = useState("");
  const [triageReason, setTriageReason] = useState("");

  const loadData = async () => {
    setLoading(true);
    try {
      const [m, f] = await Promise.all([
        fetchDashboardMetrics().catch(() => null),
        fetchFindings({
          q: searchQuery,
          severity: selectedSeverity,
          status: selectedStatus,
          scanner: selectedScanner,
          limit: 25,
        }),
      ]);
      setMetrics(m);
      setFindings(f.items);
      setTotalCount(f.total_count);
    } catch (err) {
      console.error("Failed to load findings workspace:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [searchQuery, selectedSeverity, selectedStatus, selectedScanner]);

  const handleInspectFinding = async (finding: Finding) => {
    setActiveFinding(finding);
    setDrawerLoading(true);
    try {
      const [obs, ev] = await Promise.all([
        fetchFindingObservations(finding.id).catch(() => []),
        fetchFindingEvidence(finding.id).catch(() => []),
      ]);
      setObservations(obs);
      setEvidenceList(ev);
    } finally {
      setDrawerLoading(false);
    }
  };

  const handleTriageSubmit = async () => {
    if (!activeFinding || !triageStatus) return;
    try {
      await transitionFinding(activeFinding.id, triageStatus, triageReason);
      setActiveFinding(null);
      loadData();
    } catch (err) {
      alert(`Triage failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-950 text-red-300 border-red-800";
      case "HIGH":
        return "bg-orange-950 text-orange-300 border-orange-800";
      case "MEDIUM":
        return "bg-amber-950 text-amber-300 border-amber-800";
      case "LOW":
        return "bg-sky-950 text-sky-300 border-sky-800";
      default:
        return "bg-zinc-800 text-zinc-300 border-zinc-700";
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-zinc-100">Findings Intelligence Workspace</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Review detected vulnerabilities, analyze timeline history, inspect sanitized evidence, and track remediation.
        </p>
      </div>

      {/* KPI Metrics Cards */}
      {metrics && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-6">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
            <span className="text-xs font-medium text-zinc-400">Total Findings</span>
            <p className="mt-2 text-2xl font-semibold text-zinc-100">{metrics.total_findings}</p>
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
            <span className="text-xs font-medium text-zinc-400">Active Open</span>
            <p className="mt-2 text-2xl font-semibold text-amber-400">{metrics.open_findings}</p>
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
            <span className="text-xs font-medium text-zinc-400">Resolved</span>
            <p className="mt-2 text-2xl font-semibold text-emerald-400">{metrics.resolved_findings}</p>
          </div>
          <div className="rounded-lg border border-red-900/40 bg-red-950/20 p-4">
            <span className="text-xs font-medium text-red-400">Critical</span>
            <p className="mt-2 text-2xl font-semibold text-red-400">{metrics.severity_breakdown.CRITICAL || 0}</p>
          </div>
          <div className="rounded-lg border border-orange-900/40 bg-orange-950/20 p-4">
            <span className="text-xs font-medium text-orange-400">High</span>
            <p className="mt-2 text-2xl font-semibold text-orange-400">{metrics.severity_breakdown.HIGH || 0}</p>
          </div>
          <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-4">
            <span className="text-xs font-medium text-amber-400">Medium</span>
            <p className="mt-2 text-2xl font-semibold text-amber-400">{metrics.severity_breakdown.MEDIUM || 0}</p>
          </div>
        </div>
      )}

      {/* Multi-Facet Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
        <input
          type="text"
          placeholder="Search title, endpoint, CWE, CVE…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="flex-1 min-w-[200px] rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
        />

        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value)}
          className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>

        <select
          value={selectedStatus}
          onChange={(e) => setSelectedStatus(e.target.value)}
          className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False Positive</option>
          <option value="ACCEPTED_RISK">Accepted Risk</option>
        </select>

        <select
          value={selectedScanner}
          onChange={(e) => setSelectedScanner(e.target.value)}
          className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All Scanners</option>
          <option value="nuclei">Nuclei</option>
          <option value="zap">OWASP ZAP</option>
          <option value="tls">TLS/SSL</option>
        </select>
      </div>

      {/* Findings Table */}
      <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
            <tr>
              <th className="px-4 py-3">Finding Title</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Risk Score</th>
              <th className="px-4 py-3">Target Endpoint</th>
              <th className="px-4 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-zinc-500">
                  Loading findings…
                </td>
              </tr>
            ) : findings.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-zinc-500">
                  No findings matching criteria.
                </td>
              </tr>
            ) : (
              findings.map((f) => (
                <tr key={f.id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-3 font-medium text-zinc-200">
                    <div>{f.title}</div>
                    {f.cve_ids && f.cve_ids.length > 0 && (
                      <span className="text-xs text-zinc-500">{f.cve_ids.join(", ")}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${getSeverityBadgeClass(f.severity)}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-medium text-zinc-400">{f.status}</span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {f.risk_score ? f.risk_score.toFixed(1) : "—"}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-zinc-400 truncate max-w-[200px]">
                    {f.affected_endpoint || "—"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => handleInspectFinding(f)}
                      className="rounded border border-zinc-700 bg-zinc-800 px-2.5 py-1 text-xs font-medium text-zinc-200 hover:border-zinc-500 hover:text-white"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        <div className="border-t border-zinc-800 px-4 py-3 text-xs text-zinc-400">
          Showing {findings.length} of {totalCount} findings
        </div>
      </div>

      {/* Finding Detail & Evidence Drawer */}
      {activeFinding && (
        <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col border-l border-zinc-800 bg-zinc-950 p-6 shadow-2xl overflow-y-auto">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
            <h2 className="text-lg font-semibold text-zinc-100">Finding Details</h2>
            <button
              type="button"
              onClick={() => setActiveFinding(null)}
              className="text-zinc-400 hover:text-zinc-100"
            >
              ✕
            </button>
          </div>

          <div className="mt-4 space-y-5">
            <div>
              <span className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${getSeverityBadgeClass(activeFinding.severity)}`}>
                {activeFinding.severity}
              </span>
              <h3 className="mt-2 text-xl font-bold text-zinc-100">{activeFinding.title}</h3>
              <p className="mt-1 font-mono text-xs text-zinc-400">{activeFinding.affected_endpoint}</p>
            </div>

            <div className="grid grid-cols-2 gap-4 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 text-xs">
              <div>
                <span className="text-zinc-500">CVSS Score:</span>{" "}
                <span className="font-semibold text-zinc-200">{activeFinding.cvss_score ?? "—"}</span>
              </div>
              <div>
                <span className="text-zinc-500">Calculated Risk:</span>{" "}
                <span className="font-semibold text-amber-400">{activeFinding.risk_score?.toFixed(1) ?? "—"}</span>
              </div>
              <div>
                <span className="text-zinc-500">CWE Identifier:</span>{" "}
                <span className="font-semibold text-zinc-200">{activeFinding.cwe_id || "—"}</span>
              </div>
              <div>
                <span className="text-zinc-500">Status:</span>{" "}
                <span className="font-semibold text-zinc-200">{activeFinding.status}</span>
              </div>
            </div>

            {/* Triage Action Form */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 space-y-3">
              <h4 className="text-xs font-semibold uppercase text-zinc-400">Triage Action</h4>
              <div className="flex gap-2">
                <select
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value)}
                  className="rounded border border-zinc-700 bg-zinc-800 px-2.5 py-1 text-xs text-zinc-200 focus:outline-none"
                >
                  <option value="">Select target status…</option>
                  <option value="CONFIRMED">Confirm Finding</option>
                  <option value="IN_PROGRESS">Mark In Progress</option>
                  <option value="FALSE_POSITIVE">Flag False Positive</option>
                  <option value="ACCEPTED_RISK">Accept Risk</option>
                  <option value="RESOLVED">Mark Resolved</option>
                </select>
                <input
                  type="text"
                  placeholder="Justification reason…"
                  value={triageReason}
                  onChange={(e) => setTriageReason(e.target.value)}
                  className="flex-1 rounded border border-zinc-700 bg-zinc-800 px-2.5 py-1 text-xs text-zinc-200 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleTriageSubmit}
                  className="rounded bg-emerald-600 px-3 py-1 text-xs font-semibold text-white hover:bg-emerald-500"
                >
                  Apply
                </button>
              </div>
            </div>

            {/* Sanitized Evidence Section */}
            <div>
              <h4 className="text-sm font-semibold text-zinc-200">Sanitized Evidence (ADR-0005)</h4>
              {drawerLoading ? (
                <p className="mt-2 text-xs text-zinc-500">Loading evidence…</p>
              ) : evidenceList.length === 0 ? (
                <p className="mt-2 text-xs text-zinc-500">No evidence artifacts associated with this finding.</p>
              ) : (
                <div className="mt-2 space-y-3">
                  {evidenceList.map((ev) => (
                    <div key={ev.id} className="rounded border border-zinc-800 bg-zinc-900/60 p-3 text-xs">
                      <div className="flex items-center justify-between pb-1">
                        <span className="font-semibold text-zinc-300">{ev.evidence_type}</span>
                        <span className="rounded bg-emerald-950/60 border border-emerald-800 px-1.5 py-0.5 text-[10px] text-emerald-400 font-mono">
                          REDACTED / PRESENTATION-SAFE
                        </span>
                      </div>
                      <p className="font-mono text-[11px] text-zinc-400">SHA-256: {ev.sha256_checksum.slice(0, 16)}…</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Observation Timeline Section */}
            <div>
              <h4 className="text-sm font-semibold text-zinc-200">Observation Timeline</h4>
              {drawerLoading ? (
                <p className="mt-2 text-xs text-zinc-500">Loading timeline…</p>
              ) : observations.length === 0 ? (
                <p className="mt-2 text-xs text-zinc-500">No observations recorded.</p>
              ) : (
                <div className="mt-2 space-y-2 border-l-2 border-zinc-800 pl-3">
                  {observations.map((obs) => (
                    <div key={obs.id} className="text-xs">
                      <div className="font-semibold text-zinc-300">Scanner: {obs.scanner_id}</div>
                      <div className="text-zinc-500">{new Date(obs.observed_at).toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
