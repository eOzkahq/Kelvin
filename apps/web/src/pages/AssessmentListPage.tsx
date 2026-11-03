import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchAssessments } from "../features/assessments/assessmentApi";
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

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-zinc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">
            Assessment Management Catalog
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Audit history, active security evaluation runs, and target vulnerability telemetry.
          </p>
        </div>

        <Link to="/assessments/new">
          <Button variant="primary" size="sm">
            + Launch Assessment
          </Button>
        </Link>
      </div>

      {/* Filter Bar */}
      <Card className="p-3">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="w-full sm:w-72">
            <input
              type="text"
              placeholder="Filter by assessment name or target..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 placeholder-zinc-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500"
            />
          </div>

          <div className="flex items-center gap-1.5 text-xs text-zinc-400 self-start sm:self-auto">
            <span>Status:</span>
            {["ALL", "RUNNING", "COMPLETED", "PENDING"].map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  statusFilter === status
                    ? "bg-cyan-950 text-cyan-300 font-semibold border border-cyan-800/40"
                    : "text-zinc-400 hover:text-zinc-200"
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
              <thead className="border-b border-zinc-800 text-[10px] uppercase font-mono text-zinc-500">
                <tr>
                  <th className="pb-2.5">Assessment Name</th>
                  <th className="pb-2.5">Target Address</th>
                  <th className="pb-2.5">Scan Profile</th>
                  <th className="pb-2.5">Status</th>
                  <th className="pb-2.5">Findings</th>
                  <th className="pb-2.5">Created Date</th>
                  <th className="pb-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 font-sans">
                {filtered.map((asmt) => (
                  <tr key={asmt.id} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="py-3 font-semibold text-zinc-100">
                      <Link to={`/assessments/${asmt.id}`} className="hover:text-cyan-400">
                        {asmt.name}
                      </Link>
                    </td>
                    <td className="py-3 font-mono text-zinc-400">
                      {asmt.targetAddress}
                    </td>
                    <td className="py-3 text-zinc-300 text-[11px]">
                      {asmt.profileName}
                    </td>
                    <td className="py-3">
                      <StatusPill status={asmt.status} />
                    </td>
                    <td className="py-3">
                      {asmt.totalFindings > 0 ? (
                        <div className="flex items-center gap-1.5">
                          {asmt.criticalCount > 0 && (
                            <SeverityBadge severity="CRITICAL" size="sm" showDot={false} />
                          )}
                          {asmt.highCount > 0 && (
                            <SeverityBadge severity="HIGH" size="sm" showDot={false} />
                          )}
                          <span className="text-[11px] text-zinc-400">
                            ({asmt.totalFindings} total)
                          </span>
                        </div>
                      ) : (
                        <span className="text-zinc-500 text-[11px]">0 Findings</span>
                      )}
                    </td>
                    <td className="py-3 text-zinc-500 font-mono text-[11px]">
                      {new Date(asmt.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-3 text-right">
                      <Link to={`/assessments/${asmt.id}`}>
                        <Button variant="ghost" size="sm">
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
