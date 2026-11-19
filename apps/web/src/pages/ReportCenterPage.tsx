import React, { useEffect, useState, useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  fetchReports,
  generateReport,
  getReportHtml,
  type ReportItem,
  type ReportTemplateType,
  type ReportFormat,
} from "../features/reports";
import { fetchAssessments, type AssessmentRecord } from "../features/assessments";
import { buildSecurityReportPdfBlob } from "../features/reports/pdfGenerator";
import { buildStructuredReport } from "../features/reports/reportModel";
import {
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";
import { useOptionalPlan, PLANS } from "../features/billing/PlanContext";

export default function ReportCenterPage() {
  const planCtx = useOptionalPlan();
  const activePlan = planCtx?.currentPlan ?? PLANS[0];
  const openPaywall = planCtx?.openPaywall;

  const [searchParams, setSearchParams] = useSearchParams();
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [assessments, setAssessments] = useState<AssessmentRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [sourceAssessmentId, setSourceAssessmentId] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [templateFilter, setTemplateFilter] = useState<string>("");
  const [formatFilter, setFormatFilter] = useState<string>("");

  // Generation Modal State
  const [isGenModalOpen, setIsGenModalOpen] = useState(false);
  const [assessmentId, setAssessmentId] = useState("asm-001");
  const [targetHost, setTargetHost] = useState("api.staging.kelvin-sec.internal");
  const [templateType, setTemplateType] = useState<ReportTemplateType>("EXECUTIVE_SUMMARY");
  const [format, setFormat] = useState<ReportFormat>("PDF");
  const [redactSensitiveData, setRedactSensitiveData] = useState(true);
  const [customTitle, setCustomTitle] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);

  // Preview Drawer/Modal State
  const [previewReport, setPreviewReport] = useState<ReportItem | null>(null);
  const [previewHtml, setPreviewHtml] = useState<string>("");
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setIsLoading(true);
    try {
      const [data, asmtList] = await Promise.all([
        fetchReports(),
        fetchAssessments().catch(() => [] as AssessmentRecord[]),
      ]);
      setReports(data);
      setAssessments(asmtList);
      if (asmtList.length > 0) {
        setAssessmentId(asmtList[0].id);
        setTargetHost(asmtList[0].targetAddress);
      }

      const openId = searchParams.get("open");
      const fromAsmt = searchParams.get("fromAssessment");
      if (openId) {
        const match = data.find((r) => r.id === openId);
        if (match) {
          setSourceAssessmentId(fromAsmt);
          setPreviewReport(match);
          setIsPreviewLoading(true);
          getReportHtml(match.id)
            .then(setPreviewHtml)
            .finally(() => setIsPreviewLoading(false));
          setSearchParams({}, { replace: true });
        }
      }
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setIsLoading(false);
    }
  }, [searchParams, setSearchParams]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleGenerateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsGenerating(true);

    try {
      const created = await generateReport({
        assessmentId,
        targetHost,
        templateType,
        format,
        redactSensitiveData,
        title: customTitle || undefined,
      });

      setReports((prev) => [created, ...prev]);
      setIsGenModalOpen(false);
      setCustomTitle("");
      setNotification(`Report "${created.title}" successfully generated.`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      alert(`Report generation failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleOpenPreview = async (report: ReportItem) => {
    setPreviewReport(report);
    setIsPreviewLoading(true);
    try {
      const html = await getReportHtml(report.id);
      setPreviewHtml(html);
    } catch (err) {
      alert(`Failed to load report preview: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const handleDownload = async (report: ReportItem) => {
    const htmlContent = previewReport?.id === report.id && previewHtml
      ? previewHtml
      : await getReportHtml(report.id);

    const blob =
      report.format === "PDF"
        ? buildSecurityReportPdfBlob(report)
        : new Blob([htmlContent], { type: "text/html" });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kelvin-${report.id}.${report.format.toLowerCase()}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setNotification(`Downloaded ${report.format} document for ${report.id}`);
    setTimeout(() => setNotification(null), 3000);
  };

  const handlePrintFormattedPdf = () => {
    if (!previewHtml) return;
    const printWin = window.open("", "_blank", "width=1024,height=800");
    if (!printWin) return;
    printWin.document.open();
    printWin.document.write(previewHtml);
    printWin.document.close();
    setTimeout(() => {
      printWin.focus();
      printWin.print();
    }, 250);
  };

  // Filter logic
  const filteredReports = reports.filter((r) => {
    const matchesSearch =
      !searchQuery ||
      r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.targetHost.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.assessmentId.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesTemplate = !templateFilter || r.templateType === templateFilter;
    const matchesFormat = !formatFilter || r.format === formatFilter;

    return matchesSearch && matchesTemplate && matchesFormat;
  });

  // KPI calculations
  const totalCount = reports.length;
  const execCount = reports.filter((r) => r.templateType === "EXECUTIVE_SUMMARY").length;
  const techCount = reports.filter((r) => r.templateType === "TECHNICAL_FINDINGS").length;
  const auditCount = reports.filter((r) => r.templateType === "COMPLIANCE_AUDIT").length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[var(--brand-text)]">
            Cryptographically Sealed Exports
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Assessment Report Center
          </h1>
          <p className="mt-0.5 text-xs text-zinc-400">
            Generate, inspect, print, and export cryptographically sealed HTML &amp; PDF security reports.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded-lg bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs font-mono text-emerald-300">
              {notification}
            </span>
          )}
          <Link to="/findings">
            <Button variant="secondary" size="sm">
              &larr; Findings
            </Button>
          </Link>
          <Button variant="primary" size="sm" onClick={() => setIsGenModalOpen(true)}>
            + Generate Report
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">Total Generated Reports</span>
          <p className="stat-num mt-1 text-2xl text-zinc-100">{totalCount}</p>
        </Card>
        <Card className="p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--brand-text)]">Executive Summaries</span>
          <p className="stat-num mt-1 text-2xl text-[var(--brand-text)]">{execCount}</p>
        </Card>
        <Card className="p-4 border-amber-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400">Technical Findings</span>
          <p className="stat-num mt-1 text-2xl text-amber-300">{techCount}</p>
        </Card>
        <Card className="p-4 border-emerald-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">Compliance Audits</span>
          <p className="stat-num mt-1 text-2xl text-emerald-400">{auditCount}</p>
        </Card>
      </div>

      {/* Active Tier Export Entitlements Banner */}
        <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/75 px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-zinc-200">
              <span className="h-2 w-2 rounded-full bg-[var(--brand)] shrink-0" aria-hidden="true" />
              <strong className="text-zinc-100">
                Plan {activePlan.tierNumber} ({activePlan.name}) Exports:
              </strong>
              <span className="font-mono">{activePlan.limits.reportExports.join(" · ")}</span>
              <span className="text-zinc-400">| Frameworks: {activePlan.limits.complianceFrameworks.join(", ")}</span>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <span className="font-mono text-zinc-300">{activePlan.limits.retentionDays}d Archive</span>
            {activePlan.tierNumber < 3 && openPaywall && (
              <button
                type="button"
                onClick={() => openPaywall("enterprise", "Unlock Compliance Audit Packs & 365-day Archive via Enterprise or apply eozka100.")}
                className="font-mono font-semibold text-[var(--brand-text)] hover:underline cursor-pointer"
              >
                Unlock All &rarr;
              </button>
            )}
          </div>
        </div>

        {/* Filter Bar */}
        <Card className="p-4 space-y-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
            <div className="md:col-span-5">
              <Input
                type="text"
                placeholder="Search reports by title, host, or assessment ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div className="md:col-span-3">
              <select
                value={templateFilter}
                onChange={(e) => setTemplateFilter(e.target.value)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="">All Templates</option>
                <option value="EXECUTIVE_SUMMARY">Executive Summary</option>
                <option value="TECHNICAL_FINDINGS">Technical Findings</option>
                <option value="COMPLIANCE_AUDIT">Compliance Audit</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <select
                value={formatFilter}
                onChange={(e) => setFormatFilter(e.target.value)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="">All Formats</option>
                <option value="PDF">PDF</option>
                <option value="HTML">Interactive HTML</option>
              </select>
            </div>

            <div className="md:col-span-2 flex items-center justify-end">
              {(searchQuery || templateFilter || formatFilter) && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSearchQuery("");
                    setTemplateFilter("");
                    setFormatFilter("");
                  }}
                >
                  Reset Filters
                </Button>
              )}
            </div>
          </div>
        </Card>

        {/* Reports Table */}
        <div className="overflow-x-auto rounded-xl surface-card">
          <table className="w-full text-left text-sm text-zinc-300">
            <thead className="border-b border-zinc-800/80 bg-zinc-950/90 text-[10px] font-mono tracking-wider uppercase text-zinc-400">
              <tr>
                <th className="px-4 py-3">Report Title &amp; Target</th>
                <th className="px-4 py-3">Template</th>
                <th className="px-4 py-3">Format</th>
                <th className="px-4 py-3">Redacted</th>
                <th className="px-4 py-3">File Size</th>
                <th className="px-4 py-3">Generated At</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="p-4">
                    <SkeletonLoader lines={5} />
                  </td>
                </tr>
              ) : filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8">
                    <EmptyState
                      title="No Assessment Reports Found"
                      description="No reports match your search criteria. Generate a new report from an assessment."
                      actionLabel="Generate Report"
                      onAction={() => setIsGenModalOpen(true)}
                    />
                  </td>
                </tr>
              ) : (
                filteredReports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-zinc-800/30">
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => handleOpenPreview(rep)}
                        className="text-left font-semibold text-zinc-100 hover:text-[var(--brand-text)] transition-colors cursor-pointer"
                      >
                        {rep.title}
                      </button>
                      <div className="flex items-center gap-2 mt-0.5 text-xs text-zinc-500 font-mono">
                        <span>{rep.targetHost}</span>
                        <span>&bull;</span>
                        <span>{rep.assessmentId}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs font-mono text-zinc-300">
                        {rep.templateType.replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-bold font-mono ${rep.format === "PDF"
                          ? "bg-red-950/60 border border-red-800 text-red-300"
                          : "bg-cyan-950/60 border border-cyan-800 text-cyan-300"
                          }`}
                      >
                        {rep.format}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {rep.redacted ? (
                        <span className="text-emerald-400 font-semibold">✓ Yes</span>
                      ) : (
                        <span className="text-zinc-500">Unmasked</span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-400">
                      {Math.round(rep.sizeBytes / 1024)} KB
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">
                      {new Date(rep.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <Button size="sm" variant="outline" onClick={() => handleOpenPreview(rep)}>
                          Preview
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => handleDownload(rep)}>
                          Download
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Generate Report Modal */}
        <Modal
          isOpen={isGenModalOpen}
          onClose={() => setIsGenModalOpen(false)}
          title="Generate Assessment Report"
        >
          <form onSubmit={handleGenerateSubmit} className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
            {assessments.length > 0 && (
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Select Recent Assessment Scan
                </label>
                <select
                  value={assessmentId}
                  onChange={(e) => {
                    const chosenId = e.target.value;
                    setAssessmentId(chosenId);
                    const found = assessments.find((a) => a.id === chosenId);
                    if (found) setTargetHost(found.targetAddress);
                  }}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
                >
                  {assessments.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.targetAddress}) — {a.totalFindings} findings
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Source Assessment ID <span className="text-red-400">*</span>
              </label>
              <Input
                type="text"
                value={assessmentId}
                onChange={(e) => setAssessmentId(e.target.value)}
                placeholder="e.g. asm-001"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Target Hostname <span className="text-red-400">*</span>
              </label>
              <Input
                type="text"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                placeholder="e.g. api.staging.kelvin-sec.internal"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">Report Template</label>
                <select
                  value={templateType}
                  onChange={(e) => setTemplateType(e.target.value as ReportTemplateType)}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
                >
                  <option value="EXECUTIVE_SUMMARY">Executive Risk Summary</option>
                  <option value="TECHNICAL_FINDINGS">Technical Findings &amp; Evidence</option>
                  <option value="COMPLIANCE_AUDIT">Compliance Audit Baseline</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">Output Format</label>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value as ReportFormat)}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
                >
                  <option value="PDF">PDF Document</option>
                  <option value="HTML">Interactive HTML Snapshot</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Custom Report Title (Optional)
              </label>
              <Input
                type="text"
                value={customTitle}
                onChange={(e) => setCustomTitle(e.target.value)}
                placeholder="Leave empty for automated title generation"
              />
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-zinc-300">Sanitize &amp; Redact Secrets (ADR-0005)</span>
                <p className="text-[11px] text-zinc-500">
                  Automatically masks Bearer tokens, passwords, and sensitive cookies
                </p>
              </div>
              <input
                type="checkbox"
                checked={redactSensitiveData}
                onChange={(e) => setRedactSensitiveData(e.target.checked)}
                className="rounded border-zinc-700 bg-zinc-800 text-cyan-500 focus:ring-cyan-500 h-4 w-4"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setIsGenModalOpen(false)} type="button">
                Cancel
              </Button>
              <Button variant="primary" type="submit" isLoading={isGenerating}>
                Render &amp; Sign Report
              </Button>
            </div>
          </form>
        </Modal>

        {/* Uncongested Full-Width Document Report Reader */}
        {previewReport && (() => {
          const previewDoc = buildStructuredReport(previewReport);
          return (
            <div
              className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/80 backdrop-blur-sm"
              role="dialog"
              aria-modal="true"
              aria-label={`Report Reader: ${previewReport.title}`}
              onClick={() => setPreviewReport(null)}
            >
              <div
                className="w-full max-w-5xl h-[92vh] flex flex-col rounded-2xl border border-zinc-800 bg-zinc-900 shadow-2xl overflow-hidden"
                onClick={(e) => e.stopPropagation()}
              >
                {/* Reader Top Toolbar */}
                <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-zinc-800 bg-zinc-950">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded bg-[var(--brand-bg)] border border-[var(--brand-border)] px-2 py-0.5 text-[10px] font-mono text-[var(--brand-text)] uppercase">
                        {previewReport.templateType.replace(/_/g, " ")}
                      </span>
                      <span className="rounded bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 text-[10px] font-mono text-emerald-300 font-semibold">
                        Score: {previewDoc.postureScore}/100 ({previewDoc.postureGrade})
                      </span>
                      <span className="text-xs font-mono text-zinc-500">{previewReport.id}</span>
                    </div>
                    <h2 className="text-sm sm:text-base font-semibold text-zinc-100 font-display truncate mt-1">
                      {previewReport.title}
                    </h2>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <Link
                      to={`/assessments/${encodeURIComponent(sourceAssessmentId || previewReport.assessmentId)}`}
                      onClick={() => setPreviewReport(null)}
                    >
                      <Button size="sm" variant="secondary">
                        Inspect Scan Telemetry
                      </Button>
                    </Link>
                    <Link to="/findings" onClick={() => setPreviewReport(null)}>
                      <Button size="sm" variant="secondary">
                        Findings ({previewDoc.findings.length})
                      </Button>
                    </Link>
                    <Button size="sm" variant="outline" onClick={handlePrintFormattedPdf}>
                      Print PDF
                    </Button>
                    <Button size="sm" variant="primary" onClick={() => { void handleDownload(previewReport); }}>
                      Download {previewReport.format}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setPreviewReport(null)}>
                      Close
                    </Button>
                  </div>
                </div>

                {/* Live Accuracy Ribbon */}
                <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-2 border-b border-zinc-800/80 bg-zinc-900/90 text-[11px] font-mono text-zinc-400">
                  <div className="flex flex-wrap items-center gap-3">
                    <span>Target: <strong className="text-zinc-200">{previewReport.targetHost}</strong></span>
                    <span className="text-zinc-700">|</span>
                    <span className="text-red-400">Crit: {previewDoc.severityCounts.critical}</span>
                    <span className="text-orange-400">High: {previewDoc.severityCounts.high}</span>
                    <span className="text-amber-400">Med: {previewDoc.severityCounts.medium}</span>
                    <span className="text-sky-400">Low/Info: {previewDoc.severityCounts.low + previewDoc.severityCounts.info}</span>
                  </div>
                  <div className="truncate max-w-xs text-zinc-500">
                    SHA-256: {previewReport.sha256Digest.slice(0, 18)}…
                  </div>
                </div>

                {/* Full-Width Uncluttered Document Canvas */}
                <div className="flex-1 bg-slate-200 overflow-hidden">
                  {isPreviewLoading ? (
                    <div className="h-full flex items-center justify-center p-8">
                      <SkeletonLoader lines={8} />
                    </div>
                  ) : (
                    <iframe
                      title={previewReport.title}
                      srcDoc={previewHtml}
                      sandbox="allow-same-origin"
                      className="w-full h-full border-0"
                    />
                  )}
                </div>
              </div>
            </div>
          );
        })()}
      </div>
      );
}
