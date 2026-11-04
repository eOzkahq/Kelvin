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
];

export default function FindingsWorkspacePage() {
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
      sortBy,
      sortOrder,
      page: currentPage,
      limit: pageSize,
    };

    try {
      const res = await fetchFindings(filterParams);
      setFindings(res.items);
      setTotalFindings(res.total);
      setTotalPages(res.totalPages);
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

    // Optimistic UI Update
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
      // Refresh list to confirm persistent state
      loadFindings();
    } catch (err) {
      // Rollback on failure
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

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Findings Intelligence & Search
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Multi-dimensional vulnerability exploration, triage workflows, and compliance reporting.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleExport("csv")}
            aria-label="Export findings as CSV"
          >
            Export CSV
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleExport("json")}
            aria-label="Export findings as JSON"
          >
            Export JSON
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card className="p-4 space-y-4">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
            {/* Global Search Input */}
            <div className="md:col-span-4">
              <Input
                type="text"
                placeholder="Search title, CVE, CWE, endpoint..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search findings"
              />
            </div>

            {/* Severity Filter */}
            <div className="md:col-span-2">
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value as FindingSeverity | "");
                  setCurrentPage(1);
                }}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-cyan-500 focus:outline-none"
                aria-label="Filter by Severity"
              >
                {SEVERITY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Status Filter */}
            <div className="md:col-span-2">
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value as FindingStatus | "");
                  setCurrentPage(1);
                }}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-cyan-500 focus:outline-none"
                aria-label="Filter by Status"
              >
                {STATUS_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Scanner Filter */}
            <div className="md:col-span-2">
              <select
                value={scannerFilter}
                onChange={(e) => {
                  setScannerFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-cyan-500 focus:outline-none"
                aria-label="Filter by Scanner"
              >
                {SCANNER_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Reset Filters Button */}
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
            <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-zinc-800/80 text-xs">
              <span className="text-zinc-500">Active Filters:</span>
              {debouncedSearch && (
                <span className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 text-zinc-300">
                  Search: &quot;{debouncedSearch}&quot;
                  <button
                    onClick={() => {
                      setSearchQuery("");
                      setDebouncedSearch("");
                    }}
                    className="hover:text-red-400"
                    aria-label="Remove search filter"
                  >
                    &times;
                  </button>
                </span>
              )}
              {severityFilter && (
                <span className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 text-zinc-300">
                  Severity: {severityFilter}
                  <button
                    onClick={() => setSeverityFilter("")}
                    className="hover:text-red-400"
                    aria-label="Remove severity filter"
                  >
                    &times;
                  </button>
                </span>
              )}
              {statusFilter && (
                <span className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 text-zinc-300">
                  Status: {statusFilter}
                  <button
                    onClick={() => setStatusFilter("")}
                    className="hover:text-red-400"
                    aria-label="Remove status filter"
                  >
                    &times;
                  </button>
                </span>
              )}
              {scannerFilter && (
                <span className="inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-0.5 text-zinc-300">
                  Scanner: {scannerFilter}
                  <button
                    onClick={() => setScannerFilter("")}
                    className="hover:text-red-400"
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
        <div className="flex items-center justify-between rounded-lg border border-cyan-800/70 bg-cyan-950/40 px-4 py-3 text-sm text-cyan-200 shadow-lg animate-in fade-in">
          <div className="flex items-center gap-3">
            <span className="font-semibold">{selectedIds.size} findings selected</span>
            <button
              onClick={handleClearSelection}
              className="text-xs text-cyan-400 underline hover:text-cyan-300"
            >
              Clear selection
            </button>
          </div>
          <div className="flex items-center gap-2">
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
      <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-left text-sm text-zinc-300" role="table">
          <thead className="border-b border-zinc-800 bg-zinc-900/90 text-xs uppercase text-zinc-400">
            <tr>
              <th className="w-10 px-4 py-3">
                <input
                  type="checkbox"
                  aria-label="Select all findings on current page"
                  checked={allVisibleSelected}
                  onChange={handleSelectAll}
                  className="rounded border-zinc-700 bg-zinc-800 text-cyan-500 focus:ring-cyan-500"
                />
              </th>
              <th
                className="cursor-pointer px-4 py-3 hover:text-zinc-200"
                onClick={() => handleSort("title")}
              >
                Finding Title {sortBy === "title" && (sortOrder === "asc" ? "▲" : "▼")}
              </th>
              <th
                className="cursor-pointer px-4 py-3 hover:text-zinc-200"
                onClick={() => handleSort("severity")}
              >
                Severity {sortBy === "severity" && (sortOrder === "asc" ? "▲" : "▼")}
              </th>
              <th
                className="cursor-pointer px-4 py-3 hover:text-zinc-200"
                onClick={() => handleSort("riskScore")}
              >
                Risk Score {sortBy === "riskScore" && (sortOrder === "asc" ? "▲" : "▼")}
              </th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Target Asset</th>
              <th className="px-4 py-3">Scanner</th>
              <th
                className="cursor-pointer px-4 py-3 hover:text-zinc-200"
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
                <td colSpan={9} className="p-8 text-center text-red-400">
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
                return (
                  <tr
                    key={f.id}
                    className={`transition-colors hover:bg-zinc-800/30 ${
                      isSelected ? "bg-cyan-950/20" : ""
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        aria-label={`Select finding ${f.title}`}
                        checked={isSelected}
                        onChange={() => handleSelectOne(f.id)}
                        className="rounded border-zinc-700 bg-zinc-800 text-cyan-500 focus:ring-cyan-500"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        to={`/findings/${f.id}`}
                        className="font-medium text-zinc-100 hover:text-cyan-400 hover:underline"
                      >
                        {f.title}
                      </Link>
                      <div className="flex items-center gap-2 mt-0.5 text-xs text-zinc-500">
                        {f.cweId && <span>{f.cweId}</span>}
                        {f.cveIds && f.cveIds.length > 0 && (
                          <span>{f.cveIds.slice(0, 2).join(", ")}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      <span
                        className={
                          f.riskScore >= 8.0
                            ? "text-red-400 font-bold"
                            : f.riskScore >= 6.0
                            ? "text-amber-400 font-semibold"
                            : "text-zinc-300"
                        }
                      >
                        {f.riskScore.toFixed(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusPill status={f.status} />
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-zinc-400 truncate max-w-[180px]">
                      {f.target}
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-400">{f.scanner}</td>
                    <td className="px-4 py-3 text-xs text-zinc-500">
                      {new Date(f.lastSeenAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Link
                        to={`/findings/${f.id}`}
                        className="inline-flex items-center rounded border border-zinc-700 bg-zinc-800 px-2.5 py-1 text-xs font-medium text-zinc-200 hover:border-zinc-500 hover:text-white"
                      >
                        Inspect
                      </Link>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>

        {/* Pagination & Status Footer */}
        <div className="flex flex-col sm:flex-row items-center justify-between border-t border-zinc-800 px-4 py-3 text-xs text-zinc-400 gap-3">
          <div className="flex items-center gap-2">
            <span>
              Showing {findings.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} to{" "}
              {Math.min(currentPage * pageSize, totalFindings)} of {totalFindings} findings
            </span>
            <span className="text-zinc-600">|</span>
            <label className="flex items-center gap-1">
              <span>Per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="rounded border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-zinc-200 focus:outline-none"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </label>
          </div>

          <div className="flex items-center gap-1">
            <Button
              size="sm"
              variant="secondary"
              disabled={currentPage <= 1 || isLoading}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              aria-label="Previous page"
            >
              Previous
            </Button>
            <span className="px-2 text-zinc-300">
              Page {currentPage} of {totalPages}
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
          <p className="text-sm text-zinc-400">
            Apply state transition to {selectedIds.size} selected findings across your current scope.
          </p>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Target Status
            </label>
            <select
              value={bulkTargetStatus}
              onChange={(e) => setBulkTargetStatus(e.target.value as FindingStatus)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="RESOLVED">Mark Resolved</option>
              <option value="FALSE_POSITIVE">Flag False Positive</option>
              <option value="IN_PROGRESS">Mark In Progress</option>
              <option value="ACCEPTED_RISK">Accept Risk</option>
              <option value="CONFIRMED">Confirm Finding</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Assignee (Optional)
            </label>
            <Input
              type="text"
              placeholder="e.g. analyst@kelvin.io"
              value={bulkAssignee}
              onChange={(e) => setBulkAssignee(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Audit Justification / Remediation Notes
            </label>
            <textarea
              rows={3}
              placeholder="Provide context for audit logs..."
              value={bulkJustification}
              onChange={(e) => setBulkJustification(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2.5 text-sm text-zinc-200 focus:border-cyan-500 focus:outline-none"
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
