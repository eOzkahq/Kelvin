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
import {
  ActivityIcon,
  ArrowRightIcon,
  PlusIcon,
  RefreshIcon,
} from "../components/ui/Icons";
import { useOptionalPlan, PLANS } from "../features/billing/PlanContext";

const TREND_SERIES = [14, 19, 16, 22, 28, 24, 31, 27, 35, 30, 38, 34, 41, 36];
const RESOLVED_SERIES = [8, 11, 13, 15, 19, 21, 24, 22, 29, 27, 32, 30, 36, 33];

function Sparkline({ data, stroke }: { data: number[]; stroke: string }) {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const span = max - min || 1;
  const pts = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * 76;
      const y = 22 - ((v - min) / span) * 18;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <svg width="76" height="24" viewBox="0 0 76 24" className="overflow-visible shrink-0" aria-hidden="true">
      <polyline
        fill="none"
        stroke={stroke}
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={pts}
      />
    </svg>
  );
}

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
          <SkeletonLoader lines={2} className="w-56" />
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
    { label: "Low", count: severityDistribution.low, color: "bg-sky-500", text: "text-sky-400" },
    { label: "Info", count: severityDistribution.info, color: "bg-zinc-500", text: "text-zinc-400" },
  ];

  const planCtx = useOptionalPlan();
  const activePlan = planCtx?.currentPlan ?? PLANS[0];
  const proUnlocked = activePlan.tierNumber >= 2;
  const enterpriseUnlocked = activePlan.tierNumber >= 3;

  const engines = [
    { name: "Nmap", ok: metrics.scannerReadiness?.nmap ?? true, locked: false },
    { name: "Nuclei", ok: metrics.scannerReadiness?.nuclei ?? true, locked: false },
    { name: "Trivy", ok: proUnlocked && (metrics.scannerReadiness?.trivy ?? true), locked: !proUnlocked },
    { name: "ZAP", ok: proUnlocked && (metrics.scannerReadiness?.zap ?? true), locked: !proUnlocked },
    ...(enterpriseUnlocked ? [{ name: "Custom Workers", ok: true, locked: false }] : []),
  ];
  const activeEngineCount = engines.filter((e) => e.ok).length;

  return (
    <div className="space-y-6">
      {/* Dashboard Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display">
            Security Overview
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Assessments, open findings, and remediation SLAs for the past {timeRange}.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Time Range Filter */}
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5 text-xs font-mono text-zinc-400">
            {["7d", "30d", "90d"].map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setTimeRange(range)}
                className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${timeRange === range
                  ? "bg-[var(--brand-bg)] text-[var(--brand-text)] font-semibold border border-[var(--brand-border)]"
                  : "hover:text-zinc-200 border border-transparent"
                  }`}
              >
                {range}
              </button>
            ))}
          </div>

          <Button
            variant="secondary"
            size="sm"
            leftIcon={<RefreshIcon size={13} />}
            onClick={() => refetch()}
          >
            Refresh
          </Button>

          <Link to="/assessments/new">
            <Button variant="primary" size="sm" leftIcon={<PlusIcon size={13} />}>
              Launch Scan
            </Button>
          </Link>
        </div>
      </div>

      {/* Active Plan Entitlement & Quota Strip */}
        <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/75 px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
              <span className="inline-flex items-center gap-2 font-semibold text-zinc-100">
                <span className="h-2 w-2 rounded-full bg-[var(--brand)]" aria-hidden="true" />
                Plan {activePlan.tierNumber}: {activePlan.name}
              </span>
              <span className="text-zinc-300 font-mono">{activePlan.limits.maxTargetsLabel}</span>
              <span className="text-zinc-300 font-mono">Max {activePlan.limits.maxRps} req/sec</span>
              <span className="text-zinc-400 font-mono">{activePlan.limits.workerIsolation}</span>
              <span className="text-zinc-400 font-mono">{activePlan.limits.retentionDays}d retention</span>
          </div>
          <Link
            to="/plans"
            className="font-mono font-semibold text-[var(--brand-text)] hover:underline shrink-0"
          >
            Compare / Switch Tier &rarr;
          </Link>
        </div>

        {/* Top Level KPI Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Total Assessments */}
          <Card variant="default" className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                Assessments
              </span>
              <span className="text-[11px] font-mono text-emerald-400">+12%</span>
            </div>
            <div className="mt-2.5 flex items-end justify-between gap-2">
              <span className="stat-num text-3xl text-zinc-100 leading-none">{metrics.totalAssessments}</span>
              <Sparkline data={[18, 22, 19, 25, 29, 31, 36]} stroke="#d4c9a8" />
            </div>
            <div className="mt-3 pt-2.5 border-t border-zinc-800/70 text-[11px] text-zinc-400 flex items-center gap-1.5 font-mono">
              <span className="h-1.5 w-1.5 rounded-full bg-[#d4c9a8]" />
              <span>{metrics.activeJobs} active in queue</span>
            </div>
          </Card>

          {/* Security Findings */}
          <Card variant="default" className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                Open Findings
              </span>
              <span className="text-[11px] font-mono text-red-400">
                {metrics.severityDistribution.critical} Critical
              </span>
            </div>
            <div className="mt-2.5 flex items-end justify-between gap-2">
              <span className="stat-num text-3xl text-zinc-100 leading-none">{metrics.totalFindings}</span>
              <Sparkline data={[42, 46, 44, 51, 58, 63, 68]} stroke="#f87171" />
            </div>
            <div className="mt-3 pt-2.5 border-t border-zinc-800/70 text-[11px] text-zinc-400 font-mono">
              {metrics.severityDistribution.high} High · {metrics.severityDistribution.medium} Medium
            </div>
          </Card>

          {/* SLA Breaches & Velocity */}
          <Card variant="default" className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                SLA Compliance
              </span>
              <span className="text-[11px] font-mono text-emerald-400">On Track</span>
            </div>
            <div className="mt-2.5 flex items-end justify-between gap-2">
              <span className="stat-num text-3xl text-zinc-100 leading-none">
                {metrics.slaBreaches === 0 ? "100%" : "98.2%"}
              </span>
              <Sparkline data={[94, 95, 96, 96, 97, 98, 98.2]} stroke="#34d399" />
            </div>
            <div className="mt-3 pt-2.5 border-t border-zinc-800/70 text-[11px] text-zinc-400 font-mono">
              {metrics.slaBreaches} SLA breach requiring review
            </div>
          </Card>

          {/* Scanner Engine Readiness */}
          <Card variant="default" className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
                Scanner Engines
              </span>
              <span className="text-[11px] font-mono text-emerald-400">Ready</span>
            </div>
            <div className="mt-2.5 flex items-baseline gap-2">
              <span className="stat-num text-3xl text-[var(--brand-text)] leading-none">
                {activeEngineCount}/{engines.length}
              </span>
              <span className="text-xs text-zinc-500">online</span>
            </div>
            <div className="mt-3 pt-2.5 border-t border-zinc-800/70 flex flex-wrap items-center gap-1.5">
              {engines.map((eng) => (
                <span
                  key={eng.name}
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${eng.ok
                    ? "bg-zinc-900 border-zinc-800 text-zinc-300"
                    : "bg-red-950/50 border-red-800/60 text-red-300"
                    }`}
                >
                  {eng.name}
                </span>
              ))}
            </div>
          </Card>
        </div>

        {/* 14-Day Exposure & Remediation Activity Chart */}
        <Card className="p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-zinc-800/80 mb-4">
            <div>
              <h3 className="text-sm font-semibold text-zinc-100 font-display">
                Findings Discovered vs. Remediated
              </h3>
              <p className="text-xs text-zinc-500">14-day rolling detection and closure velocity</p>
            </div>
            <div className="flex items-center gap-4 text-[11px] font-mono text-zinc-400">
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-xs bg-[var(--brand)]" />
                Discovered
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-xs bg-emerald-500/80" />
                Resolved
              </span>
            </div>
          </div>
          <div className="h-32 w-full flex items-end gap-1.5 sm:gap-2.5 pt-2">
            {TREND_SERIES.map((val, idx) => {
              const resolved = RESOLVED_SERIES[idx] ?? 0;
              const maxVal = 45;
              const discPct = Math.min(100, Math.round((val / maxVal) * 100));
              const resPct = Math.min(100, Math.round((resolved / maxVal) * 100));
              return (
                <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                  <div className="w-full flex items-end justify-center gap-0.5 sm:gap-1 h-24">
                    <div
                      className="w-1/2 max-w-[14px] rounded-t bg-[var(--brand)] opacity-80 group-hover:opacity-100 transition-opacity"
                      style={{ height: `${discPct}%` }}
                      title={`Day ${idx + 1} Discovered: ${val}`}
                    />
                    <div
                      className="w-1/2 max-w-[14px] rounded-t bg-emerald-500/65 group-hover:bg-emerald-400 transition-colors"
                      style={{ height: `${resPct}%` }}
                      title={`Day ${idx + 1} Resolved: ${resolved}`}
                    />
                  </div>
                  <span className="text-[9px] font-mono text-zinc-600 hidden sm:inline">
                    D{idx + 1}
                  </span>
                </div>
              );
            })}
          </div>
        </Card>

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

            {/* Stacked Multi-Segment Bar */}
            <div className="h-2.5 w-full rounded-full bg-zinc-900 border border-zinc-800 overflow-hidden flex mb-5">
              {severityBars.map((bar) => {
                const pct = (bar.count / totalFindings) * 100;
                if (pct <= 0) return null;
                return (
                  <div
                    key={bar.label}
                    className={`${bar.color} h-full transition-all duration-300`}
                    style={{ width: `${pct}%` }}
                    title={`${bar.label}: ${bar.count}`}
                  />
                );
              })}
            </div>

            <div className="space-y-3.5">
              {severityBars.map((bar) => {
                const pct = Math.round((bar.count / totalFindings) * 100);
                return (
                  <div key={bar.label} className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="font-medium text-zinc-300 flex items-center gap-2">
                        <span className={`h-2 w-2 rounded-full ${bar.color}`} />
                        {bar.label}
                      </span>
                      <span className="text-zinc-400 font-mono text-[11px]">
                        <strong className={bar.text}>{bar.count}</strong> ({pct}%)
                      </span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-zinc-900">
                      <div
                        className={`h-full ${bar.color} rounded-full transition-all duration-300`}
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
                <CardTitle className="flex items-center gap-2">
                  <ActivityIcon size={16} className="text-[var(--brand-text)]" />
                  <span>Active Assessment Jobs</span>
                </CardTitle>
                <CardDescription>Live scanner worker queue and sandboxed audits</CardDescription>
              </div>
              <Link
                to="/assessments"
                className="text-xs font-mono text-[var(--brand-text)] hover:text-zinc-100 inline-flex items-center gap-1"
              >
                <span>All Assessments</span>
                <ArrowRightIcon size={12} />
              </Link>
            </CardHeader>

            {activeJobs.length === 0 ? (
              <p className="text-xs text-zinc-500 py-8 text-center font-mono">
                No assessment jobs currently running in worker queue.
              </p>
            ) : (
              <div className="divide-y divide-zinc-800/70">
                {activeJobs.map((job) => (
                  <div
                    key={job.id}
                    className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-zinc-850/60 px-2 rounded-lg transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="text-xs font-semibold text-zinc-100">{job.name}</span>
                        <StatusPill status={job.status} />
                      </div>
                      <p className="text-[11px] text-zinc-400 font-mono">
                        Target: <span className="text-zinc-300">{job.target}</span> • Profile: {job.profile}
                      </p>
                      <p className="text-[11px] text-[var(--brand-text)] font-mono">
                        &rsaquo; {job.currentStage}
                      </p>
                    </div>
                    <Link to={`/assessments/${job.id}`}>
                      <Button variant="outline" size="sm">
                        Inspect Pipeline
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
            <div>
              <CardTitle>Recent Critical &amp; High Vulnerabilities</CardTitle>
              <CardDescription>Unresolved findings requiring immediate analyst triage</CardDescription>
            </div>
            <Link
              to="/findings"
              className="text-xs font-mono text-[var(--brand-text)] hover:text-zinc-100 inline-flex items-center gap-1.5"
            >
              <span>View All Findings</span>
              <ArrowRightIcon size={12} />
            </Link>
          </CardHeader>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-zinc-300">
              <thead className="border-b border-zinc-800/80 text-[10px] uppercase font-mono tracking-wider text-zinc-500">
                <tr>
                  <th className="pb-3 pr-3">Severity</th>
                  <th className="pb-3 pr-3">Vulnerability Title</th>
                  <th className="pb-3 pr-3">Target Asset</th>
                  <th className="pb-3 pr-3">Scanner</th>
                  <th className="pb-3 pr-3">Discovered</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 font-sans">
                {recentFindings.map((finding) => (
                  <tr key={finding.id} className="hover:bg-zinc-850/60 transition-colors">
                    <td className="py-3 pr-3">
                      <SeverityBadge severity={finding.severity} size="sm" />
                    </td>
                    <td className="py-3 pr-3 font-medium text-zinc-100 max-w-xs truncate">
                      <Link to={`/findings/${finding.id}`} className="hover:text-[var(--brand-text)] transition-colors">
                        {finding.title}
                      </Link>
                    </td>
                    <td className="py-3 pr-3 font-mono text-zinc-400 truncate max-w-[180px]">
                      {finding.target}
                    </td>
                    <td className="py-3 pr-3">
                      <span className="rounded bg-zinc-900 border border-zinc-800 px-2 py-0.5 font-mono text-zinc-300 uppercase text-[10px]">
                        {finding.scanner}
                      </span>
                    </td>
                    <td className="py-3 pr-3 text-zinc-500 font-mono text-[11px]">
                      {new Date(finding.discoveredAt).toLocaleDateString()}
                    </td>
                    <td className="py-3 text-right">
                      <Link to={`/findings/${finding.id}`}>
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
        </Card>
      </div>
      );
}
