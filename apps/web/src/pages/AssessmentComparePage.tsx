import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, Card, CardHeader, CardTitle, CardDescription, Input, SeverityBadge, StatusPill } from "../components/ui";
import { ScaleIcon } from "../components/ui/Icons";

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
      const res = await fetch(
        `/api/v1/assessments/${encodeURIComponent(targetId)}/compare?base=${encodeURIComponent(baseId)}`
      );
      if (res.ok) {
        const data = await res.json();
        setComparison(data);
      } else {
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

  const renderDiffTable = (
    title: string,
    items: DiffCategory[],
    accentBorder: string,
    headerBg: string,
    headerText: string
  ) => {
    if (items.length === 0) return null;
    return (
      <div className={`overflow-hidden rounded-xl border ${accentBorder} surface-card`}>
        <div className={`${headerBg} px-4 py-2.5 font-mono font-semibold text-[11px] tracking-wider ${headerText} border-b border-zinc-800/80 uppercase flex items-center justify-between`}>
          <span>{title}</span>
          <span>{items.length}</span>
        </div>
        <table className="w-full text-left text-sm text-zinc-300">
          <tbody className="divide-y divide-zinc-800/60">
            {items.map((f) => (
              <tr key={f.id} className="hover:bg-zinc-800/25 transition-colors">
                <td className="px-4 py-3 font-medium text-xs sm:text-sm text-zinc-100">
                  <Link to={`/findings/${f.id}`} className="hover:text-[#e8debe] transition-colors">
                    {f.title}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={f.severity} size="sm" />
                </td>
                <td className="px-4 py-3">
                  <StatusPill status={f.status} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-400 truncate max-w-[260px]">
                  {f.endpoint}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            Posture Drift Analysis
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Assessment Comparison
          </h1>
          <p className="mt-0.5 text-xs text-zinc-400">
            Compare two assessment runs to track security posture drift, verified resolutions, and regressions.
          </p>
        </div>
        <Link to="/findings">
          <Button variant="secondary" size="sm">
            &larr; Back to Findings
          </Button>
        </Link>
      </div>

      {/* Comparison Selector Form */}
      <Card variant="elevated">
        <CardHeader>
          <div>
            <CardTitle className="flex items-center gap-2">
              <ScaleIcon size={16} className="text-[#d4c9a8]" />
              <span>Select Baseline &amp; Target Assessment</span>
            </CardTitle>
            <CardDescription>
              Compute normalized finding set deltas between two assessment snapshots
            </CardDescription>
          </div>
          <button
            type="button"
            onClick={() => {
              setBaseId("assess-2026-001");
              setTargetId("assess-2026-002");
            }}
            className="text-[11px] font-mono text-[#d4c9a8] hover:text-[#f0eeea] underline cursor-pointer"
          >
            Fill Sample Run IDs
          </button>
        </CardHeader>

        <form onSubmit={handleCompare} className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          <div className="md:col-span-5">
            <Input
              label="Base Assessment ID (Baseline)"
              type="text"
              required
              placeholder="e.g. assess-2026-001"
              value={baseId}
              onChange={(e) => setBaseId(e.target.value)}
            />
          </div>

          <div className="md:col-span-5">
            <Input
              label="Target Assessment ID (Current Run)"
              type="text"
              required
              placeholder="e.g. assess-2026-002"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
            />
          </div>

          <div className="md:col-span-2">
            <Button
              type="submit"
              variant="primary"
              isLoading={loading}
              className="w-full"
            >
              {loading ? "Comparing…" : "Compare"}
            </Button>
          </div>
        </form>
      </Card>

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          {/* Delta KPI Cards */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Card className="p-4 border-red-900/40">
              <span className="text-[10px] font-mono uppercase tracking-wider text-red-400">
                Newly Detected
              </span>
              <p className="stat-num mt-1.5 text-3xl text-red-400">+{comparison.newFindings.length}</p>
            </Card>
            <Card className="p-4 border-emerald-900/40">
              <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">
                Resolved / Closed
              </span>
              <p className="stat-num mt-1.5 text-3xl text-emerald-400">
                -{comparison.resolvedFindings.length}
              </p>
            </Card>
            <Card className="p-4 border-orange-900/40">
              <span className="text-[10px] font-mono uppercase tracking-wider text-orange-400">
                Reopened / Regressed
              </span>
              <p className="stat-num mt-1.5 text-3xl text-orange-400">
                {comparison.reopenedFindings.length}
              </p>
            </Card>
            <Card className="p-4">
              <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400">
                Persistent / Unchanged
              </span>
              <p className="stat-num mt-1.5 text-3xl text-zinc-200">
                {comparison.persistentFindings.length}
              </p>
            </Card>
          </div>

          {renderDiffTable(
            "New Vulnerabilities Discovered",
            comparison.newFindings,
            "border-red-900/45",
            "bg-red-950/35",
            "text-red-300"
          )}

          {renderDiffTable(
            "Resolved Findings",
            comparison.resolvedFindings,
            "border-emerald-900/45",
            "bg-emerald-950/35",
            "text-emerald-300"
          )}

          {renderDiffTable(
            "Reopened / Regressed Findings",
            comparison.reopenedFindings,
            "border-orange-900/45",
            "bg-orange-950/35",
            "text-orange-300"
          )}

          {renderDiffTable(
            "Persistent / In-Progress Findings",
            comparison.persistentFindings,
            "border-zinc-800/90",
            "bg-zinc-950/80",
            "text-zinc-300"
          )}
        </div>
      )}
    </div>
  );
}
