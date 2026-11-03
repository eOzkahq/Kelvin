import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchDashboardData } from "../features/dashboard/dashboardApi";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  Button,
  SeverityBadge,
  StatusPill,
  SkeletonLoader,
  EmptyState,
} from "../components/ui";

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState("30d");

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["dashboard", timeRange],
    queryFn: ({ signal }) => fetchDashboardData(timeRange, signal),
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <SkeletonLoader lines={2} className="w-48" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <SkeletonLoader lines={4} className="h-28" />
          <SkeletonLoader lines={4} className="h-28" />
          <SkeletonLoader lines={4} className="h-28" />
          <SkeletonLoader lines={4} className="h-28" />
        </div>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <EmptyState
        title="Failed to Load Security Overview"
        description="Could not connect to the KELVIN control plane metrics API. Please verify server connectivity."
        actionLabel="Retry Connection"
        onAction={() => refetch()}
      />
    );
  }

  const { metrics, recentFindings, activeJobs } = data;
  const { severityDistribution } = metrics;
  const totalFindings = metrics.totalFindings || 1;

  const severityBars = [
    { label: "Critical", count: severityDistribution.critical, color: "bg-red-500", text: "text-red-400" },
    { label: "High", count: severityDistribution.high, color: "bg-orange-500", text: "text-orange-400" },
    { label: "Medium", count: severityDistribution.medium, color: "bg-amber-500", text: "text-amber-400" },
    { label: "Low", count: severityDistribution.low, color: "bg-blue-500", text: "text-blue-400" },
    { label: "Info", count: severityDistribution.info, color: "bg-zinc-500", text: "text-zinc-400" },
  ];

  return (
    <div className="space-y-6">
      {/* Dashboard Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-zinc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">
            Security Overview Dashboard
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Real-time vulnerability intelligence, active scanner workloads, and compliance trends.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Time Range Filter */}
          <div className="flex rounded-md border border-zinc-800 bg-zinc-900 p-0.5 text-xs font-medium text-zinc-400">
            {["7d", "30d", "90d"].map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setTimeRange(range)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  timeRange === range
                    ? "bg-cyan-950 text-cyan-300 font-semibold"
                    : "hover:text-zinc-200"
                }`}
              >
                {range}
              </button>
            ))}
          </div>

          <Button variant="secondary" size="sm" onClick={() => refetch()}>
            🔄 Refresh
          </Button>

          <Link to="/assessments/new">
            <Button variant="primary" size="sm">
              + Launch Scan
            </Button>
          </Link>
        </div>
      </div>

      {/* Top Level KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assessments */}
        <Card>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-400">Assessments Run</span>
            <span className="text-lg">🛡️</span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-zinc-100">{metrics.totalAssessments}</span>
            <span className="text-xs text-emerald-400 font-medium">+12% vs last period</span>
          </div>
          <div className="mt-2 text-[11px] text-zinc-500 flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>{metrics.activeJobs} jobs actively running</span>
          </div>
        </Card>

        {/* Security Findings */}
        <Card>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-400">Active Findings</span>
            <span className="text-lg">🚨</span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-zinc-100">{metrics.totalFindings}</span>
            <span className="text-xs text-red-400 font-medium">
              {metrics.severityDistribution.critical} Critical
            </span>
          </div>
          <div className="mt-2 text-[11px] text-zinc-500">
            {metrics.severityDistribution.high} High • {metrics.severityDistribution.medium} Medium
          </div>
        </Card>

        {/* SLA Breaches & Velocity */}
        <Card>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-400">Remediation Status</span>
            <span className="text-lg">⏱️</span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-zinc-100">
              {metrics.slaBreaches === 0 ? "100%" : "98.2%"}
            </span>
            <span className="text-xs text-emerald-400 font-medium">On Track</span>
          </div>
          <div className="mt-2 text-[11px] text-zinc-500">
            {metrics.slaBreaches} SLA breach requiring immediate escalation
          </div>
        </Card>

        {/* Scanner Engine Readiness */}
        <Card>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-400">Scanner Readiness</span>
            <span className="text-lg">⚡</span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400">4 / 4</span>
            <span className="text-xs text-zinc-400 font-medium">Engines Active</span>
          </div>
          <div className="mt-2 text-[11px] text-zinc-500 flex items-center gap-1 font-mono">
            Nmap • Nuclei • Trivy • ZAP
          </div>
        </Card>
      </div>

      {/* Charts & Breakdowns Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <div>
              <CardTitle>Severity Distribution</CardTitle>
              <CardDescription>Breakdown by canonical CVSS severity</CardDescription>
            </div>
          </CardHeader>

          <div className="space-y-3 pt-1">
            {severityBars.map((bar) => {
              const pct = Math.round((bar.count / totalFindings) * 100);
              return (
                <div key={bar.label} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="font-medium text-zinc-300 flex items-center gap-1.5">
                      <span className={`h-2 w-2 rounded-full ${bar.color}`} />
                      {bar.label}
                    </span>
                    <span className="text-zinc-400 font-mono">
                      {bar.count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-800">
                    <div
                      className={`h-full ${bar.color} transition-all duration-300`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Active Scan Workloads */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Active Assessment Jobs</CardTitle>
              <CardDescription>Live scanner worker queue and ongoing audits</CardDescription>
            </div>
          </CardHeader>

          {activeJobs.length === 0 ? (
            <p className="text-xs text-zinc-500 py-6 text-center">No assessment jobs currently running.</p>
          ) : (
            <div className="divide-y divide-zinc-800">
              {activeJobs.map((job) => (
                <div key={job.id} className="py-3 flex items-center justify-between gap-4">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-zinc-200">{job.name}</span>
                      <StatusPill status={job.status} />
                    </div>
                    <p className="text-[11px] text-zinc-400 font-mono">
                      Target: {job.target} • Profile: {job.profile}
                    </p>
                    <p className="text-[10px] text-cyan-400 font-sans">
                      {job.currentStage}
                    </p>
                  </div>
                  <Link to={`/assessments/${job.id}`}>
                    <Button variant="ghost" size="sm">
                      Inspect
                    </Button>
                  </Link>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Recent Critical & High Findings */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between w-full">
            <div>
              <CardTitle>Recent Critical & High Vulnerabilities</CardTitle>
              <CardDescription>Unresolved findings requiring immediate analyst triage</CardDescription>
            </div>
            <Link to="/findings" className="text-xs text-cyan-400 hover:text-cyan-300">
              View All Findings &rarr;
            </Link>
          </div>
        </CardHeader>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-zinc-300">
            <thead className="border-b border-zinc-800 text-[10px] uppercase font-mono text-zinc-500">
              <tr>
                <th className="pb-2">Severity</th>
                <th className="pb-2">Vulnerability Title</th>
                <th className="pb-2">Target Asset</th>
                <th className="pb-2">Scanner</th>
                <th className="pb-2">Discovered</th>
                <th className="pb-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-sans">
              {recentFindings.map((finding) => (
                <tr key={finding.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className="py-2.5">
                    <SeverityBadge severity={finding.severity} size="sm" />
                  </td>
                  <td className="py-2.5 font-medium text-zinc-100 max-w-xs truncate">
                    {finding.title}
                  </td>
                  <td className="py-2.5 font-mono text-zinc-400 truncate max-w-[180px]">
                    {finding.target}
                  </td>
                  <td className="py-2.5 font-mono text-zinc-400 uppercase text-[10px]">
                    {finding.scanner}
                  </td>
                  <td className="py-2.5 text-zinc-500">
                    {new Date(finding.discoveredAt).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 text-right">
                    <Link to={`/findings/${finding.id}`}>
                      <Button variant="ghost" size="sm">
                        View Details
                      </Button>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
