import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchAssessmentDetail,
  cancelAssessment,
} from "../features/assessments";
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

const STAGES = ["QUEUED", "PREFLIGHT", "SCANNING", "NORMALIZING", "COMPLETED"];

export default function AssessmentDetailPage() {
  const { id = "asmt-current" } = useParams();
  const queryClient = useQueryClient();
  const [logFilter, setLogFilter] = useState("");
  const [showCancelModal, setShowCancelModal] = useState(false);

  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ["assessment", id],
    queryFn: () => fetchAssessmentDetail(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      // Stop polling on terminal states (FE-26.5)
      if (
        status === "COMPLETED" ||
        status === "FAILED" ||
        status === "CANCELLED" ||
        status === "TIMED_OUT"
      ) {
        return false;
      }
      return 3000; // Poll every 3s while active
    },
  });

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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-zinc-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-zinc-100">
              {detail.name}
            </h1>
            <StatusPill status={detail.status} />
          </div>
          <p className="text-xs text-zinc-400 mt-1 font-mono">
            ID: {detail.id} • Target: <span className="text-cyan-400">{detail.targetAddress}</span> • Profile: {detail.profileName}
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

          <Link to="/findings">
            <Button variant="secondary" size="sm">
              View Findings ({detail.totalFindings})
            </Button>
          </Link>
        </div>
      </div>

      {/* Multi-Stage Visual Execution Timeline */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Execution Stage Pipeline</CardTitle>
            <CardDescription>
              Continuous pipeline progression without fabricated percentage estimates
            </CardDescription>
          </div>
        </CardHeader>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2">
          {STAGES.map((stage, idx) => {
            const isPassed = currentStageIndex > idx || detail.status === "COMPLETED";
            const isCurrent = currentStageIndex === idx && !isTerminal;

            return (
              <div
                key={stage}
                className={`p-3 rounded-lg border text-center transition-all ${
                  isCurrent
                    ? "border-cyan-500 bg-cyan-950/40 text-cyan-200"
                    : isPassed
                    ? "border-emerald-800/80 bg-emerald-950/20 text-emerald-300"
                    : "border-zinc-800 bg-zinc-900/40 text-zinc-600"
                }`}
              >
                <div className="text-[10px] uppercase font-mono tracking-wider">
                  Stage {idx + 1}
                </div>
                <div className="text-xs font-semibold mt-1 flex items-center justify-center gap-1.5">
                  {isCurrent && <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />}
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
          <Card key={task.scanner} className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-zinc-100">{task.scanner}</span>
              <StatusPill status={task.status} />
            </div>
            <p className="text-xs text-zinc-400">{task.currentActivity || "Standby"}</p>
            <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-2 border-t border-zinc-800/60 font-mono">
              <span>Findings: {task.findingsDiscovered}</span>
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
              <CardTitle>Worker Execution Logs</CardTitle>
              <CardDescription>Real-time audit telemetry streamed from runner containers</CardDescription>
            </div>
            <div className="w-full sm:w-64">
              <input
                type="text"
                placeholder="Search logs..."
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1 text-xs text-zinc-200 placeholder-zinc-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500"
              />
            </div>
          </div>
        </CardHeader>

        <div className="font-mono text-xs bg-black rounded-lg border border-zinc-800 p-4 h-64 overflow-y-auto space-y-1">
          {filteredLogs.map((log, index) => (
            <div key={index} className="flex items-start gap-3">
              <span className="text-zinc-600 select-none">{log.timestamp}</span>
              <span
                className={`font-semibold uppercase text-[10px] px-1 rounded ${
                  log.level === "ERROR"
                    ? "bg-red-950 text-red-400"
                    : log.level === "WARN"
                    ? "bg-amber-950 text-amber-400"
                    : "text-cyan-400"
                }`}
              >
                [{log.level}]
              </span>
              <span className="text-zinc-300">{log.message}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* Findings Summary Strip */}
      <Card className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="text-xs text-zinc-400 block font-medium">Discovered Vulnerabilities:</span>
          <div className="flex items-center gap-2 mt-1">
            <SeverityBadge severity="CRITICAL" size="sm" />
            <span className="text-xs text-zinc-300 font-mono">{detail.criticalCount}</span>
            <SeverityBadge severity="HIGH" size="sm" />
            <span className="text-xs text-zinc-300 font-mono">{detail.highCount}</span>
            <span className="text-xs text-zinc-500 ml-2">({detail.totalFindings} total normalized)</span>
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
        <p className="text-xs text-zinc-300">
          SIGTERM will be transmitted to all container sandboxes executing against{" "}
          <span className="font-mono text-cyan-400">{detail.targetAddress}</span>. Partial results
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
