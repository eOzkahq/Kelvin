import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  fetchRemediationTasks,
  updateTaskStatus,
  triggerVerificationScan,
  addRemediationNote,
  type RemediationTask,
  type RemediationStatus,
  type RemediationFilterParams,
} from "../features/remediation";
import {
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  SeverityBadge,
  SkeletonLoader,
  StatusPill,
} from "../components/ui";
import { SearchIcon } from "../components/ui/Icons";

const COLUMNS: { id: RemediationStatus; title: string; color: string; dot: string }[] = [
  { id: "OPEN", title: "Open / Assigned", color: "border-zinc-800/90 bg-zinc-950/50", dot: "bg-zinc-400" },
  { id: "IN_PROGRESS", title: "In Progress", color: "border-[#d4c9a8]/30 bg-[#d4c9a8]/5", dot: "bg-[#d4c9a8]" },
  { id: "BLOCKED", title: "Blocked", color: "border-amber-800/40 bg-amber-950/15", dot: "bg-amber-400" },
  { id: "VERIFICATION_PENDING", title: "Verification Pending", color: "border-purple-800/40 bg-purple-950/15", dot: "bg-purple-400" },
  { id: "RESOLVED", title: "Resolved", color: "border-emerald-800/40 bg-emerald-950/15", dot: "bg-emerald-400" },
  { id: "ACCEPTED_RISK", title: "Risk Accepted", color: "border-zinc-800/80 bg-zinc-950/60", dot: "bg-slate-400" },
];

export default function RemediationWorkspacePage() {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [viewMode, setViewMode] = useState<"kanban" | "list">("kanban");

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [assigneeFilter, setAssigneeFilter] = useState<string>("");
  const [slaFilter, setSlaFilter] = useState<"ALL" | "OVERDUE" | "BREACH_RISK" | "HEALTHY">("ALL");

  // Task detail modal state
  const [selectedTask, setSelectedTask] = useState<RemediationTask | null>(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [newNoteContent, setNewNoteContent] = useState("");
  const [isAddingNote, setIsAddingNote] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const loadTasks = useCallback(async () => {
    setIsLoading(true);
    const filterParams: RemediationFilterParams = {
      search: searchQuery || undefined,
      severity: (severityFilter as RemediationFilterParams["severity"]) || undefined,
      assignee: assigneeFilter || undefined,
      slaStatus: slaFilter !== "ALL" ? slaFilter : undefined,
    };

    try {
      const data = await fetchRemediationTasks(filterParams);
      setTasks(data);
    } catch (err) {
      console.error("Failed to load remediation tasks:", err);
    } finally {
      setIsLoading(false);
    }
  }, [searchQuery, severityFilter, assigneeFilter, slaFilter]);

  useEffect(() => {
    loadTasks();
  }, [loadTasks]);

  const handleStatusChange = async (taskId: string, newStatus: RemediationStatus) => {
    setTasks((prev) =>
      prev.map((t) => (t.id === taskId ? { ...t, status: newStatus } : t))
    );

    try {
      const updated = await updateTaskStatus(taskId, newStatus);
      if (selectedTask?.id === taskId) {
        setSelectedTask(updated);
      }
      setNotification(`Task status updated to ${newStatus}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Status update failed: ${err instanceof Error ? err.message : String(err)}`);
      loadTasks();
    }
  };

  const handleVerifyScan = async (taskId: string) => {
    setIsVerifying(true);
    try {
      const result = await triggerVerificationScan(taskId);
      setTasks((prev) =>
        prev.map((t) =>
          t.id === taskId
            ? { ...t, status: "VERIFICATION_PENDING", verificationStatus: result.status }
            : t
        )
      );
      if (selectedTask?.id === taskId) {
        setSelectedTask((prev) =>
          prev
            ? { ...prev, status: "VERIFICATION_PENDING", verificationStatus: result.status }
            : null
        );
      }
      setNotification(`Verification sweep launched (Job ID: ${result.verificationJobId})`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      alert(`Verification trigger failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAddNote = async () => {
    if (!selectedTask || !newNoteContent.trim()) return;
    setIsAddingNote(true);
    try {
      const author = localStorage.getItem("kelvin_user_email") || "current-analyst@kelvin.io";
      const note = await addRemediationNote(selectedTask.id, author, newNoteContent);
      setSelectedTask((prev) => (prev ? { ...prev, notes: [...prev.notes, note] } : null));
      setNewNoteContent("");
    } catch (err) {
      alert(`Failed to add note: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsAddingNote(false);
    }
  };

  // Metrics calculation
  const totalTasks = tasks.length;
  const overdueCount = tasks.filter((t) => t.isOverdue && t.status !== "RESOLVED").length;
  const atRiskCount = tasks.filter(
    (t) => !t.isOverdue && t.slaHoursRemaining <= 48 && t.status !== "RESOLVED"
  ).length;
  const verifyingCount = tasks.filter((t) => t.status === "VERIFICATION_PENDING").length;
  const resolvedCount = tasks.filter((t) => t.status === "RESOLVED").length;

  const renderSlaBadge = (task: RemediationTask) => {
    if (task.status === "RESOLVED" || task.status === "ACCEPTED_RISK") {
      return (
        <span className="rounded-full bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
          Closed
        </span>
      );
    }

    if (task.isOverdue) {
      return (
        <span className="rounded-full bg-red-950/80 border border-red-800 px-2 py-0.5 text-[10px] font-mono font-bold text-red-300">
          OVERDUE ({Math.abs(task.slaHoursRemaining)}h)
        </span>
      );
    }

    if (task.slaHoursRemaining <= 48) {
      return (
        <span className="rounded-full bg-amber-950/80 border border-amber-800 px-2 py-0.5 text-[10px] font-mono font-semibold text-amber-300">
          {task.slaHoursRemaining}h left
        </span>
      );
    }

    return (
      <span className="rounded-full bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 text-[10px] font-mono text-emerald-300">
        {Math.round(task.slaHoursRemaining / 24)}d left
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            SLA &amp; Verification Pipeline
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Remediation Management Workspace
          </h1>
          <p className="mt-0.5 text-xs text-zinc-400">
            Lifecycle task tracking, SLA timers, owner assignment, and automated verification scans.
          </p>
        </div>

        {/* View Mode Toggle & Feedback */}
        <div className="flex items-center gap-3">
          {notification && (
            <span className="rounded-lg bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-300 font-mono">
              {notification}
            </span>
          )}
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900/90 p-0.5">
            <button
              onClick={() => setViewMode("kanban")}
              className={`rounded-md px-3 py-1 text-xs font-medium transition-colors cursor-pointer ${
                viewMode === "kanban"
                  ? "bg-[#d4c9a8]/15 text-[#e8debe] border border-[#d4c9a8]/35"
                  : "text-zinc-400 hover:text-zinc-200 border border-transparent"
              }`}
            >
              Kanban Board
            </button>
            <button
              onClick={() => setViewMode("list")}
              className={`rounded-md px-3 py-1 text-xs font-medium transition-colors cursor-pointer ${
                viewMode === "list"
                  ? "bg-[#d4c9a8]/15 text-[#e8debe] border border-[#d4c9a8]/35"
                  : "text-zinc-400 hover:text-zinc-200 border border-transparent"
              }`}
            >
              List View
            </button>
          </div>
        </div>
      </div>

      {/* KPI Overview Strip */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-5">
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">Total Tasks</span>
          <p className="stat-num mt-1 text-2xl text-zinc-100">{totalTasks}</p>
        </Card>
        <Card className="p-4 border-red-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-red-400">Overdue SLA</span>
          <p className="stat-num mt-1 text-2xl text-red-400">{overdueCount}</p>
        </Card>
        <Card className="p-4 border-amber-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400">At-Risk (&le;48h)</span>
          <p className="stat-num mt-1 text-2xl text-amber-300">{atRiskCount}</p>
        </Card>
        <Card className="p-4 border-purple-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400">Verifying</span>
          <p className="stat-num mt-1 text-2xl text-purple-300">{verifyingCount}</p>
        </Card>
        <Card className="p-4 border-emerald-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">Resolved</span>
          <p className="stat-num mt-1 text-2xl text-emerald-400">{resolvedCount}</p>
        </Card>
      </div>

      {/* Filter Bar */}
      <Card className="p-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
          <div className="md:col-span-4 relative">
            <SearchIcon
              size={14}
              className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none"
            />
            <Input
              type="text"
              placeholder="Filter by vulnerability, target, or assignee..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
            />
          </div>

          <div className="md:col-span-2">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-xs sm:text-sm text-zinc-200 focus:outline-none focus:border-[#d4c9a8]"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <select
              value={assigneeFilter}
              onChange={(e) => setAssigneeFilter(e.target.value)}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-xs sm:text-sm text-zinc-200 focus:outline-none focus:border-[#d4c9a8]"
            >
              <option value="">All Assignees</option>
              <option value="alice@kelvin.io">alice@kelvin.io</option>
              <option value="bob@kelvin.io">bob@kelvin.io</option>
              <option value="carol@kelvin.io">carol@kelvin.io</option>
              <option value="dave@kelvin.io">dave@kelvin.io</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <select
              value={slaFilter}
              onChange={(e) => setSlaFilter(e.target.value as typeof slaFilter)}
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-xs sm:text-sm text-zinc-200 focus:outline-none focus:border-[#d4c9a8]"
            >
              <option value="ALL">All SLA Statuses</option>
              <option value="OVERDUE">Overdue Only</option>
              <option value="BREACH_RISK">At Risk (&le; 48 Hours)</option>
              <option value="HEALTHY">Healthy SLA</option>
            </select>
          </div>

          <div className="md:col-span-2 flex items-center justify-end">
            {(searchQuery || severityFilter || assigneeFilter || slaFilter !== "ALL") && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSearchQuery("");
                  setSeverityFilter("");
                  setAssigneeFilter("");
                  setSlaFilter("ALL");
                }}
              >
                Reset
              </Button>
            )}
          </div>
        </div>
      </Card>

      {/* Workspace Body */}
      {isLoading ? (
        <Card className="p-6">
          <SkeletonLoader lines={6} />
        </Card>
      ) : tasks.length === 0 ? (
        <Card className="p-8">
          <EmptyState
            title="No Remediation Tasks Found"
            description="No active remediation tickets match the applied search or SLA filters."
            actionLabel="Reset Filters"
            onAction={() => {
              setSearchQuery("");
              setSeverityFilter("");
              setSlaFilter("ALL");
            }}
          />
        </Card>
      ) : viewMode === "kanban" ? (
        /* Kanban Board View */
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-6 overflow-x-auto pb-4">
          {COLUMNS.map((col) => {
            const colTasks = tasks.filter((t) => t.status === col.id);
            return (
              <div
                key={col.id}
                className={`flex flex-col rounded-xl border p-3 min-w-[270px] lg:min-w-0 ${col.color}`}
              >
                {/* Column Header */}
                <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80 mb-3">
                  <span className="text-xs font-semibold text-zinc-200 flex items-center gap-2 font-display">
                    <span className={`h-2 w-2 rounded-full ${col.dot}`} />
                    {col.title}
                  </span>
                  <span className="rounded-full bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
                    {colTasks.length}
                  </span>
                </div>

                {/* Cards List */}
                <div className="flex-1 space-y-3 overflow-y-auto max-h-[700px] pr-1">
                  {colTasks.map((task) => {
                    const assigneeInitial = (task.assignee || "U").charAt(0).toUpperCase();
                    return (
                      <div
                        key={task.id}
                        className="rounded-xl border border-zinc-800/90 bg-zinc-900/90 p-3.5 shadow-sm hover:border-[#d4c9a8]/40 transition-all space-y-2.5"
                      >
                        <div className="flex items-center justify-between gap-1">
                          <SeverityBadge severity={task.severity} size="sm" />
                          {renderSlaBadge(task)}
                        </div>

                        <h4
                          onClick={() => {
                            setSelectedTask(task);
                            setIsDetailModalOpen(true);
                          }}
                          className="text-xs font-semibold text-zinc-100 hover:text-[#e8debe] cursor-pointer line-clamp-2 leading-snug"
                        >
                          {task.findingTitle}
                        </h4>

                        <div className="text-[11px] font-mono text-zinc-400 truncate">
                          {task.target}
                        </div>

                        <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-2 border-t border-zinc-800/70">
                          <span className="inline-flex items-center gap-1.5 truncate max-w-[130px]">
                            <span className="h-4 w-4 rounded-full bg-zinc-800 border border-zinc-700 text-[9px] font-mono font-bold text-[#d4c9a8] flex items-center justify-center shrink-0">
                              {assigneeInitial}
                            </span>
                            <span className="truncate">{task.assignee}</span>
                          </span>
                          {task.verificationStatus === "VERIFIED_RESOLVED" ? (
                            <span className="text-emerald-400 font-mono font-semibold text-[10px]">✓ Verified</span>
                          ) : task.verificationStatus === "VERIFYING" ? (
                            <span className="text-[#d4c9a8] font-mono text-[10px] animate-pulse">⟳ Scanning</span>
                          ) : null}
                        </div>

                        {/* Status Selector Dropdown */}
                        <div className="pt-1 flex items-center justify-between gap-2">
                          <select
                            value={task.status}
                            onChange={(e) =>
                              handleStatusChange(task.id, e.target.value as RemediationStatus)
                            }
                            className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-[#d4c9a8]"
                          >
                            <option value="OPEN">Move: Open</option>
                            <option value="IN_PROGRESS">Move: In Progress</option>
                            <option value="BLOCKED">Move: Blocked</option>
                            <option value="VERIFICATION_PENDING">Move: Verification</option>
                            <option value="RESOLVED">Move: Resolved</option>
                            <option value="ACCEPTED_RISK">Move: Accepted Risk</option>
                          </select>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Tabular List View */
        <div className="overflow-x-auto rounded-xl surface-card">
          <table className="w-full text-left text-sm text-zinc-300">
            <thead className="border-b border-zinc-800/80 bg-zinc-950/90 text-[10px] font-mono tracking-wider uppercase text-zinc-400">
              <tr>
                <th className="px-4 py-3">Vulnerability Title</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Target Asset</th>
                <th className="px-4 py-3">Assignee</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">SLA Status</th>
                <th className="px-4 py-3">Verification</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {tasks.map((task) => (
                <tr key={task.id} className="hover:bg-zinc-800/35">
                  <td className="px-4 py-3.5">
                    <button
                      onClick={() => {
                        setSelectedTask(task);
                        setIsDetailModalOpen(true);
                      }}
                      className="font-medium text-xs sm:text-sm text-zinc-100 hover:text-[#e8debe] text-left cursor-pointer"
                    >
                      {task.findingTitle}
                    </button>
                  </td>
                  <td className="px-4 py-3.5">
                    <SeverityBadge severity={task.severity} size="sm" />
                  </td>
                  <td className="px-4 py-3.5 font-mono text-xs text-zinc-400 truncate max-w-[180px]">
                    {task.target}
                  </td>
                  <td className="px-4 py-3.5 text-xs text-zinc-300">{task.assignee}</td>
                  <td className="px-4 py-3.5">
                    <StatusPill status={task.status} />
                  </td>
                  <td className="px-4 py-3.5">{renderSlaBadge(task)}</td>
                  <td className="px-4 py-3.5 text-xs font-mono">
                    {task.verificationStatus === "VERIFIED_RESOLVED" ? (
                      <span className="text-emerald-400 font-semibold">Automated Verified</span>
                    ) : task.verificationStatus === "VERIFYING" ? (
                      <span className="text-[#d4c9a8] animate-pulse">Sweep in progress...</span>
                    ) : (
                      <span className="text-zinc-500">Self-Reported</span>
                    )}
                  </td>
                  <td className="px-4 py-3.5 text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setSelectedTask(task);
                        setIsDetailModalOpen(true);
                      }}
                    >
                      Manage
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Task Detail & Verification Modal */}
      {selectedTask && (
        <Modal
          isOpen={isDetailModalOpen}
          onClose={() => setIsDetailModalOpen(false)}
          title="Remediation Task Workspace"
          maxWidth="lg"
        >
          <div className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
            <div className="flex items-center justify-between">
              <SeverityBadge severity={selectedTask.severity} />
              {renderSlaBadge(selectedTask)}
            </div>

            <div>
              <h3 className="text-lg font-bold text-zinc-100 font-display">{selectedTask.findingTitle}</h3>
              <p className="mt-1 font-mono text-xs text-zinc-400">{selectedTask.affectedEndpoint}</p>
              <Link
                to={`/findings/${selectedTask.findingId}`}
                className="mt-1.5 inline-block text-xs font-mono text-[#d4c9a8] hover:text-[#f0eeea] underline"
              >
                Inspect Original Finding &amp; Evidence &rarr;
              </Link>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3.5 text-xs space-y-1.5">
              <span className="font-mono font-semibold text-[#d4c9a8] uppercase tracking-wider text-[10px]">
                Remediation Guidance
              </span>
              <p className="text-zinc-300 leading-relaxed">{selectedTask.remediationGuidance}</p>
            </div>

            {/* Linked PR & Commit */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-3">
                <span className="text-[10px] font-mono uppercase text-zinc-500">Pull Request</span>
                <p className="text-zinc-200 mt-1 truncate">
                  {selectedTask.prUrl ? (
                    <a
                      href={selectedTask.prUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[#d4c9a8] underline"
                    >
                      {selectedTask.prUrl}
                    </a>
                  ) : (
                    "None linked"
                  )}
                </p>
              </div>
              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-3">
                <span className="text-[10px] font-mono uppercase text-zinc-500">Commit SHA</span>
                <p className="font-mono text-zinc-300 mt-1">
                  {selectedTask.commitSha || "Not specified"}
                </p>
              </div>
            </div>

            {/* Verification Section */}
            <div className="rounded-xl border border-[#d4c9a8]/30 bg-[#d4c9a8]/6 p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h4 className="text-xs font-mono font-semibold uppercase text-[#e8debe]">
                    Automated Verification
                  </h4>
                  <p className="text-xs text-zinc-400 mt-0.5">
                    Triggers a dedicated scanner sweep targeting this specific vulnerability
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => handleVerifyScan(selectedTask.id)}
                  isLoading={isVerifying}
                  disabled={selectedTask.verificationStatus === "VERIFYING"}
                >
                  Verify Fix
                </Button>
              </div>
              <div className="text-xs font-mono">
                <span className="text-zinc-500">Status: </span>
                <span className="font-semibold text-zinc-200">{selectedTask.verificationStatus}</span>
              </div>
            </div>

            {/* Notes Thread */}
            <div className="space-y-3 pt-2">
              <h4 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-400">
                Remediation Notes ({selectedTask.notes.length})
              </h4>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {selectedTask.notes.length === 0 ? (
                  <p className="text-xs text-zinc-500">No notes recorded yet.</p>
                ) : (
                  selectedTask.notes.map((note) => (
                    <div
                      key={note.id}
                      className="rounded-lg border border-zinc-800/80 bg-zinc-950 p-3 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between text-zinc-500 font-mono text-[10px]">
                        <span>{note.author}</span>
                        <span>{new Date(note.createdAt).toLocaleString()}</span>
                      </div>
                      <p className="text-zinc-300">{note.content}</p>
                    </div>
                  ))
                )}
              </div>

              {/* Add Note Input */}
              <div className="flex gap-2 pt-1">
                <Input
                  type="text"
                  placeholder="Add a remediation progress update..."
                  value={newNoteContent}
                  onChange={(e) => setNewNoteContent(e.target.value)}
                />
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleAddNote}
                  isLoading={isAddingNote}
                >
                  Post Note
                </Button>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
