import { useState, useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchAssessmentDetail,
  cancelAssessment,
} from "../features/assessments";
import { ensureReportForAssessment } from "../features/reports/reportsApi";
import { computePostureMarking } from "../features/reports/reportModel";
import { getLiveScanResult } from "../features/reports/liveScanStore";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  Button,
  StatusPill,
  SeverityBadge,
  Modal,
  SkeletonLoader,
  EmptyState,
} from "../components/ui";
import { RadarIcon, SearchIcon, TerminalIcon } from "../components/ui/Icons";

const STAGES = ["QUEUED", "PREFLIGHT", "SCANNING", "NORMALIZING", "COMPLETED"];

export default function AssessmentDetailPage() {
  const { id = "asmt-current" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [logFilter, setLogFilter] = useState("");
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [autoReportId, setAutoReportId] = useState<string | null>(null);

  const liveProbe = getLiveScanResult(id);

  const handleGenerateReport = async () => {
    if (!detail) return;
    setIsGeneratingReport(true);
    try {
      const created = await ensureReportForAssessment(detail.id, detail.targetAddress, detail.name);
      navigate(`/reports?open=${encodeURIComponent(created.id)}&fromAssessment=${encodeURIComponent(detail.id)}`);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ["assessment", id],
    queryFn: () => fetchAssessmentDetail(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (
        status === "COMPLETED" ||
        status === "FAILED" ||
        status === "CANCELLED" ||
        status === "TIMED_OUT"
      ) {
        return false;
      }
      return 3000;
    },
  });

  useEffect(() => {
    if (detail?.status === "COMPLETED" && !autoReportId) {
      void ensureReportForAssessment(detail.id, detail.targetAddress, detail.name).then((rep) => {
        setAutoReportId(rep.id);
      });
    }
  }, [detail?.status, detail?.id, detail?.targetAddress, detail?.name, autoReportId]);

  const cancelMutation = useMutation({
    mutationFn: () => cancelAssessment(id),
    onSuccess: (data) => {
      if (data && data.success) {
        queryClient.invalidateQueries({ queryKey: ["assessment", id] });
        setShowCancelModal(false);
      }
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <SkeletonLoader lines={2} className="w-64" />
        <SkeletonLoader lines={8} className="h-48" />
        <SkeletonLoader lines={10} className="h-64" />
      </div>
    );
  }

  if (isError || !detail) {
    return (
      <EmptyState
        title="Assessment Not Found"
        description={`Unable to locate assessment with ID "${id}".`}
        actionLabel="Back to Catalog"
        onAction={() => window.history.back()}
      />
    );
  }

  const isTerminal =
    detail.status === "COMPLETED" ||
    detail.status === "FAILED" ||
    detail.status === "CANCELLED" ||
    detail.status === "TIMED_OUT";

  const currentStageIndex = STAGES.indexOf(detail.currentStage);

  const filteredLogs = detail.logs.filter((log) =>
    log.message.toLowerCase().includes(logFilter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display">
              {detail.name}
            </h1>
            <StatusPill status={detail.status} />
          </div>
          <p className="text-xs text-zinc-400 mt-1.5 font-mono">
            ID: {detail.id} • Target: <span className="text-[#d4c9a8]">{detail.targetAddress}</span> • Profile: {detail.profileName}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!isTerminal && (
            <Button
              variant="danger"
              size="sm"
              onClick={() => setShowCancelModal(true)}
            >
              Cancel Run
            </Button>
          )}

          <Button
            variant="primary"
            size="sm"
            isLoading={isGeneratingReport}
            onClick={() => { void handleGenerateReport(); }}
          >
            {autoReportId ? "Open Auto-Generated Report" : "Open PDF Report"}
          </Button>

          <Link to="/findings">
            <Button variant="secondary" size="sm">
              View Findings ({detail.totalFindings})
            </Button>
          </Link>
        </div>
      </div>

      {detail.status === "COMPLETED" && autoReportId && (
        <div className="rounded-xl border border-emerald-800/60 bg-emerald-950/30 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-zinc-200">
            <strong className="text-emerald-400">Assessment Completed:</strong> Report{" "}
            <code className="font-mono text-[var(--brand-text)]">{autoReportId}</code> was automatically generated for{" "}
            <span className="font-mono">{detail.targetAddress}</span>.
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="primary"
              onClick={() =>
                navigate(`/reports?open=${encodeURIComponent(autoReportId)}&fromAssessment=${encodeURIComponent(detail.id)}`)
              }
            >
              View Report &rarr;
            </Button>
            <Link to="/findings">
              <Button size="sm" variant="secondary">
                Explore Findings
              </Button>
            </Link>
          </div>
        </div>
      )}

      {/* Multi-Stage Visual Execution Timeline */}
      <Card variant="elevated">
        <CardHeader>
          <div>
            <CardTitle>Execution Stage Pipeline</CardTitle>
            <CardDescription>
              Continuous sandboxed pipeline progression without fabricated percentage estimates
            </CardDescription>
          </div>
        </CardHeader>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 pt-1">
          {STAGES.map((stage, idx) => {
            const isPassed = currentStageIndex > idx || detail.status === "COMPLETED";
            const isCurrent = currentStageIndex === idx && !isTerminal;

            return (
              <div
                key={stage}
                className={`p-3.5 rounded-xl border text-center transition-all ${isCurrent
                  ? "border-[#d4c9a8]/65 bg-[#d4c9a8]/12 text-[#f0eeea] shadow-[0_0_20px_rgba(212,201,168,0.12)]"
                  : isPassed
                    ? "border-emerald-800/70 bg-emerald-950/25 text-emerald-300"
                    : "border-zinc-800/80 bg-zinc-950/50 text-zinc-500"
                  }`}
              >
                <div className="text-[10px] uppercase font-mono tracking-wider opacity-80">
                  Stage 0{idx + 1}
                </div>
                <div className="text-xs font-semibold font-mono mt-1.5 flex items-center justify-center gap-1.5">
                  {isCurrent && <span className="h-1.5 w-1.5 rounded-full bg-[#d4c9a8] animate-ping" />}
                  {isPassed && <span>✓</span>}
                  <span>{stage}</span>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Per-Scanner Worker Status */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {detail.scanners.map((task) => (
          <Card key={task.scanner} className="p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-zinc-100 flex items-center gap-2 font-display">
                <RadarIcon size={14} className="text-[#d4c9a8]" />
                {task.scanner}
              </span>
              <StatusPill status={task.status} />
            </div>
            <p className="text-xs text-zinc-400">{task.currentActivity || "Standby"}</p>
            <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-2.5 border-t border-zinc-800/70 font-mono">
              <span>Findings: <strong className="text-zinc-200">{task.findingsDiscovered}</strong></span>
              <span>{task.durationSeconds ? `${task.durationSeconds}s elapsed` : "Queued"}</span>
            </div>
          </Card>
        ))}
      </div>

      {/* Execution Logs Terminal */}
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 w-full">
            <div>
              <CardTitle className="flex items-center gap-2">
                <TerminalIcon size={15} className="text-[#d4c9a8]" />
                <span>Worker Execution Logs</span>
              </CardTitle>
              <CardDescription>Real-time audit telemetry streamed from runner containers</CardDescription>
            </div>
            <div className="relative w-full sm:w-64">
              <SearchIcon
                size={13}
                className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none"
              />
              <input
                type="text"
                placeholder="Filter log stream..."
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#d4c9a8]"
              />
            </div>
          </div>
        </CardHeader>

        <div className="rounded-xl border border-zinc-800 bg-[#060709] overflow-hidden shadow-inner">
          {/* Terminal Window Chrome */}
          <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800/80 bg-zinc-950/90 text-[10px] font-mono text-zinc-500">
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
              <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
              <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
              <span className="ml-2 text-zinc-400">kelvin-runner://sandbox-stream/{detail.id}</span>
            </div>
            <span>{filteredLogs.length} lines</span>
          </div>

          <div className="font-mono text-xs p-4 h-72 overflow-y-auto space-y-1.5">
            {filteredLogs.map((log, index) => (
              <div key={index} className="flex items-start gap-3 leading-relaxed">
                <span className="text-zinc-700 select-none w-6 text-right shrink-0">{index + 1}</span>
                <span className="text-zinc-500 select-none shrink-0">{log.timestamp}</span>
                <span
                  className={`font-semibold uppercase text-[10px] px-1.5 py-0.5 rounded shrink-0 ${log.level === "ERROR"
                    ? "bg-red-950/80 text-red-400 border border-red-900/60"
                    : log.level === "WARN"
                      ? "bg-amber-950/80 text-amber-300 border border-amber-900/60"
                      : "bg-[#d4c9a8]/10 text-[#d4c9a8] border border-[#d4c9a8]/20"
                    }`}
                >
                  {log.level}
                </span>
                <span className="text-zinc-300">{log.message}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>

              {/* Live Website Probe Findings & Posture Marking */}
              {liveProbe && (() => {
                const marking = computePostureMarking(liveProbe.findings);
                return (
          <Card className="p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-zinc-800/80">
              <div>
                <h2 className="text-sm font-semibold text-zinc-100 font-display">
                  Security Score, Marking &amp; Live Probe Findings
                </h2>
                <p className="text-xs text-zinc-400">
                  Real DNS, TLS certificate, and HTTP security header checks executed against{" "}
                  <span className="font-mono text-[var(--brand-text)]">{liveProbe.targetUrl}</span>
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-semibold text-[var(--brand-text)] bg-[var(--brand-bg)] border border-[var(--brand-border)] px-3 py-1 rounded-full">
                  Score: {marking.postureScore} / 100 · Grade {marking.postureGrade}
                </span>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/50 border border-emerald-800/60 px-2.5 py-1 rounded-full">
                  HTTP {liveProbe.httpStatus ?? "N/A"} · {liveProbe.latencyMs}ms
                </span>
              </div>
            </div>

            {/* Category Marking Breakdown */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {marking.scoringRubric.map((sc) => (
                <div key={sc.category} className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-zinc-200 truncate">{sc.category}</span>
                    <span className="font-mono font-semibold text-[var(--brand-text)]">
                      {sc.earned}/{sc.max}
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-zinc-900 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        sc.status === "PASS" ? "bg-emerald-500" : sc.status === "WARN" ? "bg-amber-500" : "bg-red-500"
                      }`}
                      style={{ width: `${(sc.earned / sc.max) * 100}%` }}
                    />
                  </div>
                  <p className="text-[10px] font-mono text-zinc-500 truncate">{sc.deductions}</p>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <span className="text-[10px] text-zinc-500 block">RESOLVED IPs</span>
                <span className="text-zinc-200 mt-1 block">
                  {liveProbe.resolvedIps.length > 0 ? liveProbe.resolvedIps.join(", ") : "Unresolved"}
                </span>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <span className="text-[10px] text-zinc-500 block">TLS POSTURE</span>
                <span className="text-zinc-200 mt-1 block">
                  {liveProbe.tls.supported
                    ? `${liveProbe.tls.protocol} · ${liveProbe.tls.cipher}`
                    : "No TLS / Plaintext"}
                </span>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <span className="text-[10px] text-zinc-500 block">CERT EXPIRY</span>
                <span className="text-zinc-200 mt-1 block">
                  {liveProbe.tls.daysRemaining !== null
                    ? `${liveProbe.tls.daysRemaining} days (${liveProbe.tls.issuer ?? "CA"})`
                    : "N/A"}
                </span>
              </div>
            </div>

            <div className="space-y-2.5">
              {liveProbe.findings.map((f) => (
                <div
                  key={f.id}
                  className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-3.5 space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span className="text-xs font-semibold text-zinc-100">{f.title}</span>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-500">
                      CVSS {f.cvss.toFixed(1)} · {f.cwe} · {f.scanner}
                    </span>
                  </div>
                  <p className="text-xs text-zinc-400">{f.description}</p>
                  <p className="text-[11px] font-mono text-[var(--brand-text)]">Evidence: {f.evidence}</p>
                  <p className="text-[11px] text-emerald-400">Remediation: {f.remediation}</p>
                </div>
              ))}
            </div>
          </Card>
        );
      })()}

      {/* Findings Summary Strip */}
      <Card variant="accent" className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400 block">
            Discovered Vulnerabilities
          </span>
          <div className="flex items-center gap-2.5 mt-1.5 flex-wrap">
            <SeverityBadge severity="CRITICAL" size="sm" />
            <span className="text-xs text-zinc-200 font-mono">{detail.criticalCount}</span>
            <SeverityBadge severity="HIGH" size="sm" />
            <span className="text-xs text-zinc-200 font-mono">{detail.highCount}</span>
            <span className="text-xs text-zinc-400 font-mono ml-1">({detail.totalFindings} total normalized)</span>
          </div>
        </div>

        <Link to="/findings">
          <Button variant="primary" size="sm">
            Inspect All Findings in Workspace &rarr;
          </Button>
        </Link>
      </Card>

      {/* Cancellation Confirmation Modal */}
      <Modal
        isOpen={showCancelModal}
        onClose={() => setShowCancelModal(false)}
        title="Cancel Security Assessment"
        description="Terminating an active assessment halts worker containers immediately."
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setShowCancelModal(false)}>
              Keep Running
            </Button>
            <Button
              variant="danger"
              size="sm"
              isLoading={cancelMutation.isPending}
              onClick={() => cancelMutation.mutate()}
            >
              Confirm Termination
            </Button>
          </>
        }
      >
        <p className="text-xs text-zinc-300 leading-relaxed">
          SIGTERM will be transmitted to all container sandboxes executing against{" "}
          <span className="font-mono text-[#d4c9a8]">{detail.targetAddress}</span>. Partial results
          already recorded will be preserved in the findings repository.
        </p>
        {cancelMutation.isError && (
          <div className="mt-3 text-xs text-red-400 bg-red-950/40 p-2.5 rounded border border-red-900/50">
            Failed to terminate assessment: {cancelMutation.error?.message || "Internal server error"}
          </div>
        )}
      </Modal>
    </div>
  );
}
