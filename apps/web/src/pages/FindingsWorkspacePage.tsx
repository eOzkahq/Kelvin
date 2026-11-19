import React, { useEffect, useState, useTransition, useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  fetchFindings,
  batchUpdateFindings,
  exportFindings,
  type Finding,
  type FindingSeverity,
  type FindingStatus,
  type FindingsFilterParams,
} from "../features/findings";
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
import { DownloadIcon, LockIcon, SearchIcon } from "../components/ui/Icons";
import { useOptionalPlan, PLANS } from "../features/billing/PlanContext";

const SEVERITY_OPTIONS: { label: string; value: FindingSeverity | "" }[] = [
  { label: "All Severities", value: "" },
  { label: "Critical", value: "CRITICAL" },
  { label: "High", value: "HIGH" },
  { label: "Medium", value: "MEDIUM" },
  { label: "Low", value: "LOW" },
  { label: "Info", value: "INFO" },
];

const STATUS_OPTIONS: { label: string; value: FindingStatus | "" }[] = [
  { label: "All Statuses", value: "" },
  { label: "Open", value: "OPEN" },
  { label: "Confirmed", value: "CONFIRMED" },
  { label: "In Progress", value: "IN_PROGRESS" },
  { label: "Resolved", value: "RESOLVED" },
  { label: "False Positive", value: "FALSE_POSITIVE" },
  { label: "Risk Accepted", value: "ACCEPTED_RISK" },
];

const SCANNER_OPTIONS: { label: string; value: string }[] = [
  { label: "All Scanners", value: "" },
  { label: "Nuclei", value: "Nuclei" },
  { label: "OWASP ZAP", value: "OWASP-ZAP" },
  { label: "Nmap", value: "Nmap" },
  { label: "Trivy", value: "Trivy" },
  { label: "TLS-Check", value: "TLS-Check" },
  { label: "Custom Workers", value: "Custom-Workers" },
];

export default function FindingsWorkspacePage() {
  const planCtx = useOptionalPlan();
  const activePlan = planCtx?.currentPlan ?? PLANS[2];
  const openPaywall = planCtx?.openPaywall;

  const [searchParams, setSearchParams] = useSearchParams();
  const [, startTransition] = useTransition();

  // Search & Filter State synchronized with URL
  const [searchQuery, setSearchQuery] = useState(searchParams.get("q") ?? "");
  const [debouncedSearch, setDebouncedSearch] = useState(searchQuery);
  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | "">(
    (searchParams.get("severity") as FindingSeverity) ?? ""
  );
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "">(
    (searchParams.get("status") as FindingStatus) ?? ""
  );
  const [scannerFilter, setScannerFilter] = useState(searchParams.get("scanner") ?? "");
  const [targetFilter, setTargetFilter] = useState(searchParams.get("target") ?? "");

  // Sorting & Pagination
  const [sortBy, setSortBy] = useState<"severity" | "riskScore" | "lastSeenAt" | "title">(
    (searchParams.get("sortBy") as "severity" | "riskScore" | "lastSeenAt" | "title") ?? "riskScore"
  );
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">(
    (searchParams.get("sortOrder") as "asc" | "desc") ?? "desc"
  );
  const [currentPage, setCurrentPage] = useState<number>(
    parseInt(searchParams.get("page") ?? "1", 10) || 1
  );
  const [pageSize, setPageSize] = useState<number>(
    parseInt(searchParams.get("limit") ?? "25", 10) || 25
  );

  // Findings list and loading state
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalFindings, setTotalFindings] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [lockedCounts, setLockedCounts] = useState<{ pro: number; enterprise: number }>({ pro: 0, enterprise: 0 });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Row selection & Bulk Action State
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  const [bulkTargetStatus, setBulkTargetStatus] = useState<FindingStatus>("RESOLVED");
  const [bulkJustification, setBulkJustification] = useState("");
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [isBulkSubmitting, setIsBulkSubmitting] = useState(false);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchQuery);
      setCurrentPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Sync state to URL search parameters
  const updateUrlParams = useCallback(() => {
    const params = new URLSearchParams();
    if (debouncedSearch) params.set("q", debouncedSearch);
    if (severityFilter) params.set("severity", severityFilter);
    if (statusFilter) params.set("status", statusFilter);
    if (scannerFilter) params.set("scanner", scannerFilter);
    if (targetFilter) params.set("target", targetFilter);
    if (sortBy !== "riskScore") params.set("sortBy", sortBy);
    if (sortOrder !== "desc") params.set("sortOrder", sortOrder);
    if (currentPage > 1) params.set("page", currentPage.toString());
    if (pageSize !== 25) params.set("limit", pageSize.toString());

    startTransition(() => {
      setSearchParams(params, { replace: true });
    });
  }, [
    debouncedSearch,
    severityFilter,
    statusFilter,
    scannerFilter,
    targetFilter,
    sortBy,
    sortOrder,
    currentPage,
    pageSize,
    setSearchParams,
  ]);

  // Load findings from API
  const loadFindings = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    const filterParams: FindingsFilterParams = {
      search: debouncedSearch,
      severity: severityFilter,
      status: statusFilter,
      scanner: scannerFilter,
      target: targetFilter,
      maxTier: activePlan.tierNumber as 1 | 2 | 3,
      sortBy,
      sortOrder,
      page: currentPage,
      limit: pageSize,
    };

    try {
      const res = await fetchFindings(filterParams);
      const items = Array.isArray(res) ? res : (res?.items ?? []);
      setFindings(items);
      setTotalFindings(res?.total ?? items.length);
      setTotalPages(res?.totalPages ?? 1);
      setLockedCounts(res?.lockedTierCounts ?? { pro: 0, enterprise: 0 });
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setIsLoading(false);
    }
  }, [
    debouncedSearch,
    severityFilter,
    statusFilter,
    scannerFilter,
    targetFilter,
    activePlan.tierNumber,
    sortBy,
    sortOrder,
    currentPage,
    pageSize,
  ]);

  useEffect(() => {
    loadFindings();
    updateUrlParams();
  }, [loadFindings, updateUrlParams]);

  // Sort toggle handler
  const handleSort = (column: "severity" | "riskScore" | "lastSeenAt" | "title") => {
    if (sortBy === column) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(column);
      setSortOrder(column === "title" ? "asc" : "desc");
    }
    setCurrentPage(1);
  };

  // Selection handlers
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      const allIds = new Set(findings.map((f) => f.id));
      setSelectedIds(allIds);
    } else {
      setSelectedIds(new Set());
    }
  };

  const handleSelectOne = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelectedIds(next);
  };

  const handleClearSelection = () => {
    setSelectedIds(new Set());
  };

  // Reset all filters
  const handleResetFilters = () => {
    setSearchQuery("");
    setDebouncedSearch("");
    setSeverityFilter("");
    setStatusFilter("");
    setScannerFilter("");
    setTargetFilter("");
    setSortBy("riskScore");
    setSortOrder("desc");
    setCurrentPage(1);
  };

  const hasActiveFilters = Boolean(
    debouncedSearch || severityFilter || statusFilter || scannerFilter || targetFilter
  );

  // Bulk update submission
  const handleBulkSubmit = async () => {
    if (selectedIds.size === 0) return;
    setIsBulkSubmitting(true);

    const idsToUpdate = Array.from(selectedIds);
    const previousFindings = [...findings];

    setFindings((prev) =>
      prev.map((f) =>
        idsToUpdate.includes(f.id)
          ? {
            ...f,
            status: bulkTargetStatus,
            assignee: bulkAssignee || f.assignee,
          }
          : f
      )
    );

    try {
      await batchUpdateFindings({
        findingIds: idsToUpdate,
        status: bulkTargetStatus,
        assignee: bulkAssignee || undefined,
        justification: bulkJustification,
      });
      setSelectedIds(new Set());
      setIsBulkModalOpen(false);
      setBulkJustification("");
      setBulkAssignee("");
      loadFindings();
    } catch (err) {
      setFindings(previousFindings);
      alert(`Bulk update failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsBulkSubmitting(false);
    }
  };

  // Export handlers
  const handleExport = async (format: "csv" | "json") => {
    try {
      const content = await exportFindings(format, {
        search: debouncedSearch,
        severity: severityFilter,
        status: statusFilter,
        scanner: scannerFilter,
        target: targetFilter,
        sortBy,
        sortOrder,
      });

      const mimeType = format === "json" ? "application/json" : "text/csv;charset=utf-8;";
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `kelvin-findings-${new Date().toISOString().slice(0, 10)}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const allVisibleSelected =
    findings.length > 0 && findings.every((f) => selectedIds.has(f.id));

  const visibleCritical = findings.filter((f) => f.severity === "CRITICAL").length;
  const visibleHigh = findings.filter((f) => f.severity === "HIGH").length;
  const visibleOpen = findings.filter((f) => f.status === "OPEN" || f.status === "CONFIRMED").length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            Normalized Schema v1
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Findings Intelligence &amp; Search
          </h1>
          <p className="mt-0.5 text-xs text-zinc-400">
            Multi-dimensional vulnerability exploration, triage workflows, and compliance exports.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<DownloadIcon size={13} />}
            onClick={() => handleExport("csv")}
            aria-label="Export findings as CSV"
          >
            Export CSV
          </Button>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<DownloadIcon size={13} />}
            onClick={() => handleExport("json")}
            aria-label="Export findings as JSON"
          >
            Export JSON
          </Button>
        </div>
      </div>

      {/* Quick Severity Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
            Matching Findings
          </span>
          <p className="stat-num text-2xl text-zinc-100 mt-1">{totalFindings}</p>
        </Card>
        <Card className="p-4 border-red-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-red-400">
            Critical (Page)
          </span>
          <p className="stat-num text-2xl text-red-400 mt-1">{visibleCritical}</p>
        </Card>
        <Card className="p-4 border-orange-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-orange-400">
            High (Page)
          </span>
          <p className="stat-num text-2xl text-orange-400 mt-1">{visibleHigh}</p>
        </Card>
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#d4c9a8]">
            Unresolved (Page)
          </span>
          <p className="stat-num text-2xl text-[#e8debe] mt-1">{visibleOpen}</p>
        </Card>
      </div>

      {/* Tier Finding Depth Coverage Bar */}
        <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/75 px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs">
          <div className="flex flex-wrap items-center gap-2 text-zinc-200">
              <span className="h-2 w-2 rounded-full bg-[var(--brand)] shrink-0" aria-hidden="true" />
              <strong className="text-zinc-100">
                Plan {activePlan.tierNumber} ({activePlan.name}) Findings Scope:
              </strong>
              <span className="font-mono">{activePlan.scanners.join(" · ")}</span>
              {(lockedCounts.pro > 0 || lockedCounts.enterprise > 0) && (
                <span className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-[11px] font-mono text-zinc-300">
                  <LockIcon size={10} />
                  {lockedCounts.pro + lockedCounts.enterprise} deeper findings locked (
                  {lockedCounts.pro > 0 ? `${lockedCounts.pro} Pro ZAP/Trivy` : ""}
                  {lockedCounts.pro > 0 && lockedCounts.enterprise > 0 ? " + " : ""}
                  {lockedCounts.enterprise > 0 ? `${lockedCounts.enterprise} Enterprise Perimeter` : ""})
                </span>
              )}
          </div>
          {(lockedCounts.pro > 0 || lockedCounts.enterprise > 0) && openPaywall && (
            <button
              type="button"
              onClick={() =>
                openPaywall(
                  activePlan.tierNumber === 1 ? "pro" : "enterprise",
                  "Unlock deeper OWASP ZAP, Trivy SBOM, and Custom-Workers perimeter findings for free with coupon eozka100.",
                )
              }
              className="font-mono font-semibold text-[var(--brand-text)] hover:underline shrink-0 cursor-pointer"
            >
              Unlock Deeper Findings (eozka100) &rarr;
            </button>
          )}
        </div>

        {/* Filter and Search Bar */}
        <Card className="p-4 space-y-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
            <div className="md:col-span-4 relative">
              <SearchIcon
                size={14}
                className="absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none"
              />
              <Input
                type="text"
                placeholder="Search title, CVE, CWE, endpoint..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search findings"
                className="pl-9"
              />
            </div>

            <div className="md:col-span-2">
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value as FindingSeverity | "");
                  setCurrentPage(1);
                }}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-xs sm:text-sm text-zinc-200 focus:border-[#d4c9a8] focus:outline-none"
                aria-label="Filter by Severity"
              >
                {SEVERITY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value as FindingStatus | "");
                  setCurrentPage(1);
                }}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-xs sm:text-sm text-zinc-200 focus:border-[#d4c9a8] focus:outline-none"
                aria-label="Filter by Status"
              >
                {STATUS_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <select
                value={scannerFilter}
                onChange={(e) => {
                  setScannerFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-xs sm:text-sm text-zinc-200 focus:border-[#d4c9a8] focus:outline-none"
                aria-label="Filter by Scanner"
              >
                {SCANNER_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2 flex items-center justify-end">
              {hasActiveFilters && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleResetFilters}
                  className="w-full text-zinc-400 hover:text-white"
                >
                  Reset Filters
                </Button>
              )}
            </div>
          </div>

          {/* Active Filter Chips */}
          {hasActiveFilters && (
            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-800/80 text-xs">
              <span className="text-[10px] font-mono uppercase text-zinc-500">Active Filters:</span>
              {debouncedSearch && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-900 border border-zinc-700 px-2.5 py-0.5 text-zinc-300 font-mono text-[11px]">
                  Search: &quot;{debouncedSearch}&quot;
                  <button
                    onClick={() => {
                      setSearchQuery("");
                      setDebouncedSearch("");
                    }}
                    className="hover:text-red-400 cursor-pointer"
                    aria-label="Remove search filter"
                  >
                    &times;
                  </button>
                </span>
              )}
              {severityFilter && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-900 border border-zinc-700 px-2.5 py-0.5 text-zinc-300 font-mono text-[11px]">
                  Severity: {severityFilter}
                  <button
                    onClick={() => setSeverityFilter("")}
                    className="hover:text-red-400 cursor-pointer"
                    aria-label="Remove severity filter"
                  >
                    &times;
                  </button>
                </span>
              )}
              {statusFilter && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-900 border border-zinc-700 px-2.5 py-0.5 text-zinc-300 font-mono text-[11px]">
                  Status: {statusFilter}
                  <button
                    onClick={() => setStatusFilter("")}
                    className="hover:text-red-400 cursor-pointer"
                    aria-label="Remove status filter"
                  >
                    &times;
                  </button>
                </span>
              )}
              {scannerFilter && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-900 border border-zinc-700 px-2.5 py-0.5 text-zinc-300 font-mono text-[11px]">
                  Scanner: {scannerFilter}
                  <button
                    onClick={() => setScannerFilter("")}
                    className="hover:text-red-400 cursor-pointer"
                    aria-label="Remove scanner filter"
                  >
                    &times;
                  </button>
                </span>
              )}
            </div>
          )}
        </Card>

        {/* Bulk Action Sticky Bar */}
        {selectedIds.size > 0 && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-[#d4c9a8]/45 bg-[#d4c9a8]/10 px-4 py-3 text-sm text-[#f0eeea] shadow-lg backdrop-blur-md">
            <div className="flex items-center gap-3">
              <span className="font-semibold font-mono text-xs uppercase tracking-wider text-[#e8debe]">
                {selectedIds.size} findings selected
              </span>
              <button
                onClick={handleClearSelection}
                className="text-xs text-zinc-300 underline hover:text-white cursor-pointer"
              >
                Clear selection
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  setBulkTargetStatus("RESOLVED");
                  setIsBulkModalOpen(true);
                }}
              >
                Mark Resolved
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  setBulkTargetStatus("FALSE_POSITIVE");
                  setIsBulkModalOpen(true);
                }}
              >
                Flag False Positive
              </Button>
              <Button
                size="sm"
                variant="primary"
                onClick={() => {
                  setBulkTargetStatus("IN_PROGRESS");
                  setIsBulkModalOpen(true);
                }}
              >
                Batch Triage...
              </Button>
            </div>
          </div>
        )}

        {/* Findings Data Table */}
        <div className="overflow-x-auto rounded-xl surface-card">
          <table className="w-full text-left text-sm text-zinc-300" role="table">
            <thead className="border-b border-zinc-800/80 bg-zinc-950/90 text-[10px] font-mono tracking-wider uppercase text-zinc-400">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    aria-label="Select all findings on current page"
                    checked={allVisibleSelected}
                    onChange={handleSelectAll}
                    className="rounded border-zinc-700 bg-zinc-800"
                  />
                </th>
                <th
                  className="cursor-pointer px-4 py-3 hover:text-[#e8debe] transition-colors"
                  onClick={() => handleSort("title")}
                >
                  Finding Title {sortBy === "title" && (sortOrder === "asc" ? "▲" : "▼")}
                </th>
                <th
                  className="cursor-pointer px-4 py-3 hover:text-[#e8debe] transition-colors"
                  onClick={() => handleSort("severity")}
                >
                  Severity {sortBy === "severity" && (sortOrder === "asc" ? "▲" : "▼")}
                </th>
                <th
                  className="cursor-pointer px-4 py-3 hover:text-[#e8debe] transition-colors"
                  onClick={() => handleSort("riskScore")}
                >
                  Risk Score {sortBy === "riskScore" && (sortOrder === "asc" ? "▲" : "▼")}
                </th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Target Asset</th>
                <th className="px-4 py-3">Scanner</th>
                <th
                  className="cursor-pointer px-4 py-3 hover:text-[#e8debe] transition-colors"
                  onClick={() => handleSort("lastSeenAt")}
                >
                  Last Detected {sortBy === "lastSeenAt" && (sortOrder === "asc" ? "▲" : "▼")}
                </th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="p-4">
                    <SkeletonLoader lines={5} />
                  </td>
                </tr>
              ) : errorMessage ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-red-400 text-xs">
                    {errorMessage}
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8">
                    <EmptyState
                      title="No findings match your filters"
                      description="Try loosening your search keywords or resetting the severity and status filters."
                      actionLabel={hasActiveFilters ? "Reset All Filters" : undefined}
                      onAction={hasActiveFilters ? handleResetFilters : undefined}
                    />
                  </td>
                </tr>
              ) : (
                findings.map((f) => {
                  const isSelected = selectedIds.has(f.id);
                  const riskPct = Math.min(100, Math.max(0, (f.riskScore / 10) * 100));
                  const riskBarColor =
                    f.riskScore >= 8.0
                      ? "bg-red-500"
                      : f.riskScore >= 6.0
                        ? "bg-amber-400"
                        : "bg-[#d4c9a8]";

                  return (
                    <tr
                      key={f.id}
                      className={`transition-colors hover:bg-zinc-800/35 ${isSelected ? "bg-[#d4c9a8]/8" : ""
                        }`}
                    >
                      <td className="px-4 py-3.5">
                        <input
                          type="checkbox"
                          aria-label={`Select finding ${f.title}`}
                          checked={isSelected}
                          onChange={() => handleSelectOne(f.id)}
                          className="rounded border-zinc-700 bg-zinc-800"
                        />
                      </td>
                      <td className="px-4 py-3.5">
                        <Link
                          to={`/findings/${f.id}`}
                          className="font-medium text-xs sm:text-sm text-zinc-100 hover:text-[#e8debe] transition-colors"
                        >
                          {f.title}
                        </Link>
                        <div className="flex items-center gap-2 mt-1 text-[11px] font-mono text-zinc-500">
                          {f.cweId && (
                            <span className="rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 text-zinc-400">
                              {f.cweId}
                            </span>
                          )}
                          {f.cveIds && f.cveIds.length > 0 && (
                            <span className="text-[#d4c9a8]">{f.cveIds.slice(0, 2).join(", ")}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <SeverityBadge severity={f.severity} size="sm" />
                      </td>
                      <td className="px-4 py-3.5 font-mono text-xs">
                        <div className="flex items-center gap-2">
                          <span
                            className={
                              f.riskScore >= 8.0
                                ? "text-red-400 font-bold"
                                : f.riskScore >= 6.0
                                  ? "text-amber-300 font-semibold"
                                  : "text-zinc-300"
                            }
                          >
                            {f.riskScore.toFixed(1)}
                          </span>
                          <div className="w-12 h-1.5 rounded-full bg-zinc-900 overflow-hidden hidden xl:block">
                            <div className={`h-full ${riskBarColor}`} style={{ width: `${riskPct}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <StatusPill status={f.status} />
                      </td>
                      <td className="px-4 py-3.5 text-xs font-mono text-zinc-400 truncate max-w-[180px]">
                        {f.target}
                      </td>
                      <td className="px-4 py-3.5">
                        <span className="rounded bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[10px] font-mono uppercase text-zinc-300">
                          {f.scanner}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-xs font-mono text-zinc-500">
                        {new Date(f.lastSeenAt).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <Link to={`/findings/${f.id}`}>
                          <Button variant="outline" size="sm">
                            Inspect
                          </Button>
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>

          {/* Pagination & Status Footer */}
          <div className="flex flex-col sm:flex-row items-center justify-between border-t border-zinc-800/80 px-4 py-3 text-xs text-zinc-400 gap-3 bg-zinc-950/60">
            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span>
                Showing {findings.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} to{" "}
                {Math.min(currentPage * pageSize, totalFindings)} of {totalFindings} findings
              </span>
              <span className="text-zinc-700">|</span>
              <label className="flex items-center gap-1.5">
                <span>Per page:</span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-zinc-200 focus:outline-none"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </label>
            </div>

            <div className="flex items-center gap-1.5">
              <Button
                size="sm"
                variant="secondary"
                disabled={currentPage <= 1 || isLoading}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                aria-label="Previous page"
              >
                Previous
              </Button>
              <span className="px-2.5 text-xs font-mono text-zinc-300">
                Page {currentPage} / {totalPages}
              </span>
              <Button
                size="sm"
                variant="secondary"
                disabled={currentPage >= totalPages || isLoading}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                aria-label="Next page"
              >
                Next
              </Button>
            </div>
          </div>
        </div>

        {/* Batch Triage Confirmation Modal */}
        <Modal
          isOpen={isBulkModalOpen}
          onClose={() => setIsBulkModalOpen(false)}
          title={`Batch Triage (${selectedIds.size} findings)`}
        >
          <div className="space-y-4">
            <p className="text-xs text-zinc-400">
              Apply state transition to {selectedIds.size} selected findings across your current scope.
            </p>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Target Status
              </label>
              <select
                value={bulkTargetStatus}
                onChange={(e) => setBulkTargetStatus(e.target.value as FindingStatus)}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-[#d4c9a8]"
              >
                <option value="RESOLVED">Mark Resolved</option>
                <option value="FALSE_POSITIVE">Flag False Positive</option>
                <option value="IN_PROGRESS">Mark In Progress</option>
                <option value="ACCEPTED_RISK">Accept Risk</option>
                <option value="CONFIRMED">Confirm Finding</option>
              </select>
            </div>

            <div>
              <Input
                label="Assignee (Optional)"
                type="text"
                placeholder="e.g. analyst@kelvin.io"
                value={bulkAssignee}
                onChange={(e) => setBulkAssignee(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Audit Justification / Remediation Notes
              </label>
              <textarea
                rows={3}
                placeholder="Provide context for audit logs..."
                value={bulkJustification}
                onChange={(e) => setBulkJustification(e.target.value)}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950/75 p-2.5 text-sm text-zinc-200 focus:border-[#d4c9a8] focus:outline-none"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button
                variant="secondary"
                onClick={() => setIsBulkModalOpen(false)}
                disabled={isBulkSubmitting}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleBulkSubmit}
                isLoading={isBulkSubmitting}
              >
                Apply Updates
              </Button>
            </div>
          </div>
        </Modal>
      </div>
      );
}
