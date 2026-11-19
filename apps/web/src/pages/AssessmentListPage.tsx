import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchAssessments } from "../features/assessments";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  Button,
  StatusPill,
  SeverityBadge,
  SkeletonLoader,
  EmptyState,
} from "../components/ui";
import { PlusIcon, SearchIcon } from "../components/ui/Icons";

export default function AssessmentListPage() {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const { data: assessments, isLoading, isError, refetch } = useQuery({
    queryKey: ["assessments"],
    queryFn: fetchAssessments,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <SkeletonLoader lines={2} className="w-48" />
        <SkeletonLoader lines={6} className="h-64" />
      </div>
    );
  }

  if (isError || !assessments) {
    return (
      <EmptyState
        title="Failed to Load Assessments"
        description="Unable to retrieve the assessment catalog. Please retry."
        actionLabel="Retry"
        onAction={() => refetch()}
      />
    );
  }

  const filtered = assessments.filter((asmt) => {
    const matchesSearch =
      asmt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asmt.targetAddress.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === "ALL" || asmt.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const runningCount = assessments.filter((a) => a.status === "RUNNING").length;
  const completedCount = assessments.filter((a) => a.status === "COMPLETED").length;
  const totalFindingsCount = assessments.reduce((sum, a) => sum + (a.totalFindings || 0), 0);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            Scan Orchestration
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Assessment Management Catalog
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Audit history, active security evaluation runs, and target vulnerability telemetry.
          </p>
        </div>

        <Link to="/assessments/new">
          <Button variant="primary" size="sm" leftIcon={<PlusIcon size={13} />}>
            Launch Assessment
          </Button>
        </Link>
      </div>

      {/* Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
            Total Runs
          </span>
          <p className="stat-num text-2xl text-zinc-100 mt-1">{assessments.length}</p>
        </Card>
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#d4c9a8]">
            Actively Running
          </span>
          <p className="stat-num text-2xl text-[#e8debe] mt-1">{runningCount}</p>
        </Card>
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">
            Completed Sweeps
          </span>
          <p className="stat-num text-2xl text-emerald-400 mt-1">{completedCount}</p>
        </Card>
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
            Findings Discovered
          </span>
          <p className="stat-num text-2xl text-zinc-100 mt-1">{totalFindingsCount}</p>
        </Card>
      </div>

      {/* Filter Bar */}
      <Card className="p-3.5">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative w-full sm:w-80">
            <SearchIcon
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none"
            />
            <input
              type="text"
              placeholder="Filter by assessment name or target..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-zinc-950/75 border border-zinc-800 rounded-lg pl-9 pr-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8]"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5 text-xs text-zinc-400 self-start sm:self-auto">
            <span className="text-[10px] font-mono uppercase text-zinc-500 mr-1">Status:</span>
            {["ALL", "RUNNING", "COMPLETED", "PENDING"].map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors cursor-pointer border ${
                  statusFilter === status
                    ? "bg-[#d4c9a8]/15 text-[#e8debe] font-semibold border-[#d4c9a8]/40"
                    : "border-transparent text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* Catalog Table */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Assessments ({filtered.length})</CardTitle>
            <CardDescription>Target vulnerability assessments in active workspace</CardDescription>
          </div>
        </CardHeader>

        {filtered.length === 0 ? (
          <EmptyState
            title="No Assessments Matching Filter"
            description="Adjust your search query or launch a new security scan."
            actionLabel="Clear Filter"
            onAction={() => {
              setSearchTerm("");
              setStatusFilter("ALL");
            }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-zinc-300">
              <thead className="border-b border-zinc-800/80 text-[10px] uppercase font-mono tracking-wider text-zinc-500">
                <tr>
                  <th className="pb-3 pr-3">Assessment Name</th>
                  <th className="pb-3 pr-3">Target Address</th>
                  <th className="pb-3 pr-3">Scan Profile</th>
                  <th className="pb-3 pr-3">Status</th>
                  <th className="pb-3 pr-3">Findings</th>
                  <th className="pb-3 pr-3">Created Date</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 font-sans">
                {filtered.map((asmt) => (
                  <tr key={asmt.id} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="py-3.5 pr-3 font-semibold text-zinc-100">
                      <Link to={`/assessments/${asmt.id}`} className="hover:text-[#e8debe] transition-colors">
                        {asmt.name}
                      </Link>
                    </td>
                    <td className="py-3.5 pr-3 font-mono text-zinc-400">
                      {asmt.targetAddress}
                    </td>
                    <td className="py-3.5 pr-3">
                      <span className="rounded bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[11px] font-mono text-zinc-300">
                        {asmt.profileName}
                      </span>
                    </td>
                    <td className="py-3.5 pr-3">
                      <StatusPill status={asmt.status} />
                    </td>
                    <td className="py-3.5 pr-3">
                      {asmt.totalFindings > 0 ? (
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {asmt.criticalCount > 0 && (
                            <SeverityBadge severity="CRITICAL" size="sm" showDot={false} />
                          )}
                          {asmt.highCount > 0 && (
                            <SeverityBadge severity="HIGH" size="sm" showDot={false} />
                          )}
                          <span className="text-[11px] font-mono text-zinc-400">
                            ({asmt.totalFindings} total)
                          </span>
                        </div>
                      ) : (
                        <span className="text-zinc-500 font-mono text-[11px]">0 Findings</span>
                      )}
                    </td>
                    <td className="py-3.5 pr-3 text-zinc-500 font-mono text-[11px]">
                      {new Date(asmt.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 text-right">
                      <Link to={`/assessments/${asmt.id}`}>
                        <Button variant="outline" size="sm">
                          Inspect
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
