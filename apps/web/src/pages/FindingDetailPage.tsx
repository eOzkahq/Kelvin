import { useEffect, useState, useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import {
  getFindingDetail,
  transitionFindingStatus,
  sanitizeEvidence,
  type FindingDetail,
  type FindingStatus,
} from "../features/findings";
import {
  Button,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  EmptyState,
  Input,
  Modal,
  SeverityBadge,
  SkeletonLoader,
  StatusPill,
} from "../components/ui";

type TabKey = "overview" | "risk" | "evidence" | "observations" | "remediation" | "audit";

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();

  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");

  // Evidence state
  const [selectedEvidenceIndex, setSelectedEvidenceIndex] = useState(0);
  const [showRawUnsanitized, setShowRawUnsanitized] = useState(false);

  // Triage modal state
  const [isTriageModalOpen, setIsTriageModalOpen] = useState(false);
  const [triageStatus, setTriageStatus] = useState<FindingStatus>("IN_PROGRESS");
  const [triageJustification, setTriageJustification] = useState("");
  const [triageAssignee, setTriageAssignee] = useState("");
  const [triageDueDate, setTriageDueDate] = useState("");
  const [isSubmittingTriage, setIsSubmittingTriage] = useState(false);
  const [triageSuccessMessage, setTriageSuccessMessage] = useState<string | null>(null);

  const loadFinding = useCallback(async () => {
    if (!id) return;
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const data = await getFindingDetail(id);
      setFinding(data);
      setTriageStatus(data.status);
      setTriageAssignee(data.assignee || "");
      if (data.dueDate) {
        setTriageDueDate(data.dueDate.slice(0, 10));
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to load finding details");
    } finally {
      setIsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadFinding();
  }, [loadFinding]);

  const handleTriageSubmit = async () => {
    if (!id || !finding) return;
    if (!triageJustification.trim()) {
      alert("Please provide a justification for this status transition.");
      return;
    }

    setIsSubmittingTriage(true);
    try {
      const updated = await transitionFindingStatus(
        id,
        triageStatus,
        triageJustification,
        triageAssignee || undefined,
        triageDueDate ? new Date(triageDueDate).toISOString() : undefined
      );
      setFinding(updated);
      setIsTriageModalOpen(false);
      setTriageJustification("");
      setTriageSuccessMessage(`Status updated to ${triageStatus}`);
      setTimeout(() => setTriageSuccessMessage(null), 4000);
    } catch (err) {
      alert(`Status transition failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSubmittingTriage(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-32 bg-zinc-800 animate-pulse rounded" />
        <Card className="p-6">
          <SkeletonLoader lines={6} />
        </Card>
      </div>
    );
  }

  if (errorMessage || !finding) {
    return (
      <div className="space-y-6">
        <Link to="/findings" className="text-xs text-cyan-400 hover:text-cyan-300">
          &larr; Back to Findings
        </Link>
        <EmptyState
          title="Finding Not Found"
          description={errorMessage || `No finding matching identifier "${id}" was found.`}
          actionLabel="Back to Findings"
          onAction={() => window.history.back()}
        />
      </div>
    );
  }

  const evidenceList = finding.evidence || [];
  const observationsList = finding.observations || [];
  const auditTrailList = finding.auditTrail || [];
  const selectedEvidence = evidenceList[selectedEvidenceIndex] || evidenceList[0];

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb Navigation & Notification */}
      <div className="flex items-center justify-between">
        <Link
          to="/findings"
          className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-cyan-400 transition-colors"
        >
          <span>&larr;</span> Back to Findings Workspace
        </Link>
        {triageSuccessMessage && (
          <div className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
            {triageSuccessMessage}
          </div>
        )}
      </div>

      {/* Finding Header Card */}
      <Card variant="accent" className="p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <StatusPill status={finding.status} />
              <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs font-mono text-zinc-400">
                Risk Score: {(finding.riskScore ?? 0).toFixed(1)} / 10.0
              </span>
              {typeof finding.cvssScore === "number" && (
                <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs font-mono text-zinc-400">
                  CVSS: {finding.cvssScore.toFixed(1)}
                </span>
              )}
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-zinc-100">
              {finding.title}
            </h1>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
              <div>
                <span className="text-zinc-500">Target:</span>{" "}
                <span className="font-mono text-zinc-300">{finding.target || "N/A"}</span>
              </div>
              <div>
                <span className="text-zinc-500">Endpoint:</span>{" "}
                <span className="font-mono text-zinc-300">{finding.affectedEndpoint || "N/A"}</span>
              </div>
              <div>
                <span className="text-zinc-500">Scanner:</span>{" "}
                <span className="text-zinc-300">{finding.scanner || "Automated"}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button
              variant="primary"
              onClick={() => setIsTriageModalOpen(true)}
              aria-label="Triage or update finding status"
            >
              Triage Finding...
            </Button>
          </div>
        </div>

        {/* Fingerprint & Quick Metadata */}
        <div className="mt-4 pt-4 border-t border-zinc-800 flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
          <div className="flex items-center gap-2">
            <span>Fingerprint:</span>
            <code className="rounded bg-zinc-950 px-2 py-0.5 font-mono text-zinc-400">
              {finding.fingerprint || "—"}
            </code>
          </div>
          <div>
            <span>First Detected: {finding.firstSeenAt && !isNaN(new Date(finding.firstSeenAt).getTime()) ? new Date(finding.firstSeenAt).toLocaleString() : "—"}</span>
            <span className="mx-2">|</span>
            <span>Last Verified: {finding.lastSeenAt && !isNaN(new Date(finding.lastSeenAt).getTime()) ? new Date(finding.lastSeenAt).toLocaleString() : "—"}</span>
          </div>
        </div>
      </Card>

      {/* Detail Tab Navigation */}
      <div className="flex border-b border-zinc-800 gap-2 overflow-x-auto">
        {(
          [
            { key: "overview", label: "Overview & Description" },
            { key: "risk", label: "Risk Explainability" },
            { key: "evidence", label: `Evidence (${evidenceList.length})` },
            { key: "observations", label: `Observations (${observationsList.length})` },
            { key: "remediation", label: "Remediation & SLA" },
            { key: "audit", label: `Audit Trail (${auditTrailList.length})` },
          ] as { key: TabKey; label: string }[]
        ).map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`whitespace-nowrap px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Overview & Description */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <Card className="p-6">
            <CardHeader>
              <CardTitle>Vulnerability Description</CardTitle>
              <CardDescription>Formal security analysis and behavioral footprint</CardDescription>
            </CardHeader>
            <p className="text-sm text-zinc-300 leading-relaxed">
              {finding.description ||
                "Vulnerability detected during active automated security assessment sweep. Please review sanitized payload proof-of-concept in the Evidence tab."}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6 pt-6 border-t border-zinc-800">
              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-4">
                <span className="text-xs font-medium text-zinc-500">Common Weakness Enumeration</span>
                <p className="mt-1 text-sm font-semibold text-zinc-200">{finding.cweId || "N/A"}</p>
              </div>
              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-4">
                <span className="text-xs font-medium text-zinc-500">CVE References</span>
                <p className="mt-1 text-sm font-semibold text-zinc-200">
                  {finding.cveIds && finding.cveIds.length > 0
                    ? finding.cveIds.join(", ")
                    : "No public CVE mapped"}
                </p>
              </div>
              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-4">
                <span className="text-xs font-medium text-zinc-500">Current Assignee</span>
                <p className="mt-1 text-sm font-semibold text-zinc-200">
                  {finding.assignee || "Unassigned"}
                </p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tab 2: Risk Explainability */}
      {activeTab === "risk" && (
        <div className="space-y-6">
          <Card className="p-6">
            <CardHeader>
              <CardTitle>Mathematical Risk Explainability</CardTitle>
              <CardDescription>
                Canonical multi-factor algorithm decomposing composite risk score
              </CardDescription>
            </CardHeader>

            <div className="rounded-lg border border-cyan-800/50 bg-cyan-950/20 p-4 font-mono text-xs text-cyan-300 mb-6">
              <code>{finding.riskExplainability.formula}</code>
            </div>

            <p className="text-sm text-zinc-400 mb-6">
              {finding.riskExplainability.rationale}
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-zinc-300">
                <thead className="border-b border-zinc-800 text-xs uppercase text-zinc-500">
                  <tr>
                    <th className="py-2.5 px-3">Factor</th>
                    <th className="py-2.5 px-3">Weight / Value</th>
                    <th className="py-2.5 px-3">Impact Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {finding.riskExplainability.contributingFactors.map((cf, i) => (
                    <tr key={i} className="hover:bg-zinc-800/20">
                      <td className="py-3 px-3 font-medium text-zinc-200">{cf.factor}</td>
                      <td className="py-3 px-3 font-mono text-cyan-400">{cf.weight}</td>
                      <td className="py-3 px-3 text-xs text-zinc-400">{cf.impact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* Tab 3: Evidence Viewer */}
      {activeTab === "evidence" && (
        <div className="space-y-6">
          <Card className="p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between pb-4 border-b border-zinc-800">
              <div>
                <CardTitle>Sanitized Evidence Viewer (ADR-0005)</CardTitle>
                <CardDescription>
                  Presentation-safe proof-of-concept payload inspection with secret masking
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 text-xs text-emerald-400 font-mono">
                  PRESENTATION-SAFE
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowRawUnsanitized(!showRawUnsanitized)}
                >
                  {showRawUnsanitized ? "Show Redacted" : "Inspect Raw Payload"}
                </Button>
              </div>
            </div>

            {/* Evidence Selector Pills */}
            <div className="flex items-center gap-2 mt-4 overflow-x-auto pb-2">
              {evidenceList.map((ev, index) => (
                <button
                  key={ev.id}
                  onClick={() => setSelectedEvidenceIndex(index)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                    selectedEvidenceIndex === index
                      ? "bg-zinc-700 text-white"
                      : "bg-zinc-800/60 text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  {ev.title} ({ev.evidenceType})
                </button>
              ))}
            </div>

            {selectedEvidence && (
              <div className="mt-4 space-y-3">
                <div className="flex items-center justify-between text-xs text-zinc-500">
                  <span>SHA-256 Checksum: <code className="text-zinc-400">{selectedEvidence.sha256}</code></span>
                  <span>Captured: {new Date(selectedEvidence.timestamp || selectedEvidence.createdAt || Date.now()).toLocaleString()}</span>
                </div>

                <div className="relative overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs text-zinc-300">
                  <pre className="whitespace-pre-wrap leading-relaxed">
                    {showRawUnsanitized
                      ? (selectedEvidence.rawPayload || selectedEvidence.sanitizedPayload)
                      : (selectedEvidence.sanitizedPayload || sanitizeEvidence(selectedEvidence.rawPayload || "").sanitized)}
                  </pre>
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Tab 4: Historical Observations */}
      {activeTab === "observations" && (
        <div className="space-y-6">
          <Card className="p-6">
            <CardHeader>
              <CardTitle>Historical Scan Observations</CardTitle>
              <CardDescription>
                Chronological persistence across recurring assessment executions
              </CardDescription>
            </CardHeader>

            <div className="relative border-l-2 border-zinc-800 pl-4 space-y-6 mt-4">
              {observationsList.map((obs) => (
                <div key={obs.id} className="relative">
                  <span className="absolute -left-[21px] top-1 h-3 w-3 rounded-full border-2 border-zinc-900 bg-cyan-400" />
                  <div className="text-xs text-zinc-500">{new Date(obs.observedAt || obs.timestamp || Date.now()).toLocaleString()}</div>
                  <h4 className="text-sm font-semibold text-zinc-200 mt-0.5">{obs.assessmentTitle}</h4>
                  <div className="flex items-center gap-2 mt-1 text-xs text-zinc-400">
                    <span>Scanner: <strong className="text-zinc-300">{obs.scanner}</strong></span>
                    <span>&bull;</span>
                    <span>Observation Status: <strong className="text-zinc-300">{obs.status}</strong></span>
                    <span>&bull;</span>
                    <span>Evidence Items: {obs.evidenceCount}</span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Tab 5: Remediation & SLA */}
      {activeTab === "remediation" && (
        <div className="space-y-6">
          <Card className="p-6">
            <CardHeader>
              <CardTitle>Remediation Guidance & SLA Tracking</CardTitle>
              <CardDescription>Remediation steps, ownership, and target compliance SLA</CardDescription>
            </CardHeader>

            <div className="space-y-4 text-sm text-zinc-300">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
                <h4 className="text-xs font-semibold uppercase text-zinc-400 mb-2">Recommended Fix</h4>
                <p className="leading-relaxed">
                  {finding.remediation ||
                    "Review target endpoints, patch vulnerable packages to latest versions, and enforce secure configuration baselines."}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
                  <span className="text-xs text-zinc-500">Remediation SLA Policy</span>
                  <p className="text-lg font-bold text-zinc-100 mt-1">
                    {finding.remediationSlaDays ?? 30} Days ({finding.severity} Severity)
                  </p>
                  <p className="text-xs text-zinc-400 mt-1">
                    Target Due Date:{" "}
                    {finding.dueDate ? new Date(finding.dueDate).toLocaleDateString() : "Unassigned"}
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
                  <span className="text-xs text-zinc-500">Current Assigned Engineer</span>
                  <p className="text-lg font-bold text-zinc-100 mt-1">
                    {finding.assignee || "Unassigned"}
                  </p>
                  <p className="text-xs text-zinc-400 mt-1">
                    Status: <strong className="text-zinc-300">{finding.status}</strong>
                  </p>
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tab 6: Audit Trail */}
      {activeTab === "audit" && (
        <div className="space-y-6">
          <Card className="p-6">
            <CardHeader>
              <CardTitle>Immutable Finding Audit Trail</CardTitle>
              <CardDescription>
                Tamper-evident record of state transitions, justifications, and triage decisions
              </CardDescription>
            </CardHeader>

            <div className="space-y-4 mt-4">
              {auditTrailList.map((entry) => (
                <div
                  key={entry.id}
                  className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-4 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-zinc-200">{entry.action}</span>
                    <span className="text-zinc-500">{new Date(entry.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="text-zinc-400">
                    Actor: <code className="text-cyan-400">{entry.actor}</code>
                    {entry.fromStatus && entry.toStatus && (
                      <span className="ml-2">
                        ({entry.fromStatus} &rarr; {entry.toStatus})
                      </span>
                    )}
                  </div>
                  {entry.justification && (
                    <p className="mt-2 text-zinc-300 italic border-l-2 border-zinc-700 pl-2">
                      &quot;{entry.justification}&quot;
                    </p>
                  )}
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Triage Action Modal */}
      <Modal
        isOpen={isTriageModalOpen}
        onClose={() => setIsTriageModalOpen(false)}
        title="Triage Vulnerability State"
      >
        <div className="space-y-4">
          <p className="text-sm text-zinc-400">
            Update lifecycle status, ownership, or SLA compliance target for this vulnerability.
          </p>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">Target Status</label>
            <select
              value={triageStatus}
              onChange={(e) => setTriageStatus(e.target.value as FindingStatus)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="OPEN">Open</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="ACCEPTED_RISK">Accepted Risk</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Assignee Email (Optional)
            </label>
            <Input
              type="text"
              placeholder="e.g. security-engineer@kelvin.io"
              value={triageAssignee}
              onChange={(e) => setTriageAssignee(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Remediation Due Date
            </label>
            <Input
              type="date"
              value={triageDueDate}
              onChange={(e) => setTriageDueDate(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Audit Justification / Rationalization <span className="text-red-400">*</span>
            </label>
            <textarea
              rows={3}
              placeholder="State the technical rationale for this triage decision..."
              value={triageJustification}
              onChange={(e) => setTriageJustification(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2.5 text-sm text-zinc-200 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="secondary"
              onClick={() => setIsTriageModalOpen(false)}
              disabled={isSubmittingTriage}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleTriageSubmit}
              isLoading={isSubmittingTriage}
            >
              Apply Status Transition
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
