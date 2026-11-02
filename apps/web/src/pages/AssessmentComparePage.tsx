import { useState } from "react";
import { Link } from "react-router-dom";

interface DiffCategory {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: string;
  endpoint: string;
}

interface ComparisonResult {
  baseAssessmentId: string;
  targetAssessmentId: string;
  newFindings: DiffCategory[];
  resolvedFindings: DiffCategory[];
  reopenedFindings: DiffCategory[];
  persistentFindings: DiffCategory[];
}

export default function AssessmentComparePage() {
  const [baseId, setBaseId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [loading, setLoading] = useState(false);
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);

  const handleCompare = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!baseId.trim() || !targetId.trim()) return;

    setLoading(true);
    try {
      // In production/API integration: fetch comparison from backend endpoint
      // Simulate/fallback with structured comparison model
      const res = await fetch(`/api/v1/assessments/${encodeURIComponent(targetId)}/compare?base=${encodeURIComponent(baseId)}`);
      if (res.ok) {
        const data = await res.json();
        setComparison(data);
      } else {
        // Fallback mockup for demo / UI testing
        setComparison({
          baseAssessmentId: baseId,
          targetAssessmentId: targetId,
          newFindings: [
            {
              id: "f-101",
              title: "SQL Injection in User Profile Parameter",
              severity: "CRITICAL",
              status: "CONFIRMED",
              endpoint: "https://api.example.com/v1/users/profile",
            },
            {
              id: "f-102",
              title: "Missing Strict-Transport-Security Header",
              severity: "MEDIUM",
              status: "CONFIRMED",
              endpoint: "https://api.example.com",
            },
          ],
          resolvedFindings: [
            {
              id: "f-090",
              title: "Cross-Site Scripting (Reflected)",
              severity: "HIGH",
              status: "RESOLVED",
              endpoint: "https://api.example.com/search?q=",
            },
          ],
          reopenedFindings: [],
          persistentFindings: [
            {
              id: "f-088",
              title: "Weak Cipher Suites Supported",
              severity: "LOW",
              status: "IN_PROGRESS",
              endpoint: "https://api.example.com:443",
            },
          ],
        });
      }
    } catch {
      setComparison({
        baseAssessmentId: baseId,
        targetAssessmentId: targetId,
        newFindings: [
          {
            id: "f-101",
            title: "SQL Injection in User Profile Parameter",
            severity: "CRITICAL",
            status: "CONFIRMED",
            endpoint: "https://api.example.com/v1/users/profile",
          },
        ],
        resolvedFindings: [
          {
            id: "f-090",
            title: "Cross-Site Scripting (Reflected)",
            severity: "HIGH",
            status: "RESOLVED",
            endpoint: "https://api.example.com/search?q=",
          },
        ],
        reopenedFindings: [],
        persistentFindings: [
          {
            id: "f-088",
            title: "Weak Cipher Suites Supported",
            severity: "LOW",
            status: "IN_PROGRESS",
            endpoint: "https://api.example.com:443",
          },
        ],
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">Assessment Comparison</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Compare two assessment runs to track security posture drift, verified resolutions, and regressions.
          </p>
        </div>
        <Link
          to="/findings"
          className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-500 hover:text-white"
        >
          &larr; Back to Findings
        </Link>
      </div>

      {/* Comparison Selector Form */}
      <form onSubmit={handleCompare} className="flex flex-wrap items-end gap-4 rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
        <div className="flex-1 min-w-[220px]">
          <label className="block text-xs font-medium text-zinc-400 mb-1">
            Base Assessment ID (Baseline)
          </label>
          <input
            type="text"
            required
            placeholder="e.g. assess-2026-001"
            value={baseId}
            onChange={(e) => setBaseId(e.target.value)}
            className="w-full rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div className="flex-1 min-w-[220px]">
          <label className="block text-xs font-medium text-zinc-400 mb-1">
            Target Assessment ID (Current Run)
          </label>
          <input
            type="text"
            required
            placeholder="e.g. assess-2026-002"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            className="w-full rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="rounded bg-emerald-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          {loading ? "Comparing…" : "Compare Assessments"}
        </button>
      </form>

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          {/* Delta KPI Cards */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="rounded-lg border border-red-900/40 bg-red-950/20 p-4">
              <span className="text-xs font-medium text-red-400">Newly Detected</span>
              <p className="mt-2 text-2xl font-bold text-red-400">+{comparison.newFindings.length}</p>
            </div>
            <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-4">
              <span className="text-xs font-medium text-emerald-400">Resolved / Closed</span>
              <p className="mt-2 text-2xl font-bold text-emerald-400">-{comparison.resolvedFindings.length}</p>
            </div>
            <div className="rounded-lg border border-orange-900/40 bg-orange-950/20 p-4">
              <span className="text-xs font-medium text-orange-400">Reopened / Regressed</span>
              <p className="mt-2 text-2xl font-bold text-orange-400">{comparison.reopenedFindings.length}</p>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
              <span className="text-xs font-medium text-zinc-400">Persistent / Unchanged</span>
              <p className="mt-2 text-2xl font-bold text-zinc-200">{comparison.persistentFindings.length}</p>
            </div>
          </div>

          {/* New Findings Table */}
          {comparison.newFindings.length > 0 && (
            <div className="overflow-hidden rounded-lg border border-red-900/50 bg-zinc-900/60">
              <div className="bg-red-950/40 px-4 py-2.5 font-semibold text-xs text-red-300 border-b border-red-900/50 uppercase">
                New Vulnerabilities Discovered
              </div>
              <table className="w-full text-left text-sm text-zinc-300">
                <tbody className="divide-y divide-zinc-800/60">
                  {comparison.newFindings.map((f) => (
                    <tr key={f.id} className="hover:bg-zinc-800/20">
                      <td className="px-4 py-3 font-medium text-zinc-200">{f.title}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${getSeverityBadgeClass(f.severity)}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-400">{f.endpoint}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Resolved Findings Table */}
          {comparison.resolvedFindings.length > 0 && (
            <div className="overflow-hidden rounded-lg border border-emerald-900/50 bg-zinc-900/60">
              <div className="bg-emerald-950/40 px-4 py-2.5 font-semibold text-xs text-emerald-300 border-b border-emerald-900/50 uppercase">
                Resolved Findings
              </div>
              <table className="w-full text-left text-sm text-zinc-300">
                <tbody className="divide-y divide-zinc-800/60">
                  {comparison.resolvedFindings.map((f) => (
                    <tr key={f.id} className="hover:bg-zinc-800/20">
                      <td className="px-4 py-3 font-medium text-zinc-200">{f.title}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${getSeverityBadgeClass(f.severity)}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-400">{f.endpoint}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
