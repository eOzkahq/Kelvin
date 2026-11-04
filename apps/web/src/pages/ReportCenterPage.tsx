import React, { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  fetchReports,
  generateReport,
  getReportHtml,
  type ReportItem,
  type ReportTemplateType,
  type ReportFormat,
} from "../features/reports";
import {
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";

export default function ReportCenterPage() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

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
      const data = await fetchReports();
      setReports(data);
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

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

  const handleDownload = (report: ReportItem) => {
    const mime = report.format === "PDF" ? "application/pdf" : "text/html";
    const dummyBlob = new Blob(
      [
        report.format === "PDF"
          ? `%PDF-1.4\n%KELVIN-SEALED-SECURITY-REPORT\n${report.title}\nSHA256: ${report.sha256Digest}`
          : previewHtml || "<html><body><h1>Report</h1></body></html>",
      ],
      { type: mime }
    );
    const url = URL.createObjectURL(dummyBlob);
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
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Assessment Report Center
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Generate, preview, audit, and securely export cryptographically sealed HTML &amp; PDF assessment reports.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
              {notification}
            </span>
          )}
          <Link
            to="/findings"
            className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-500 hover:text-white"
          >
            &larr; Findings
          </Link>
          <Button variant="primary" onClick={() => setIsGenModalOpen(true)}>
            + Generate Report
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
          <span className="text-xs text-zinc-400 font-medium">Total Generated Reports</span>
          <p className="mt-1 text-2xl font-bold text-zinc-100">{totalCount}</p>
        </div>
        <div className="rounded-lg border border-cyan-900/40 bg-cyan-950/20 p-3">
          <span className="text-xs text-cyan-400 font-medium">Executive Summaries</span>
          <p className="mt-1 text-2xl font-bold text-cyan-300">{execCount}</p>
        </div>
        <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-3">
          <span className="text-xs text-amber-400 font-medium">Technical Findings</span>
          <p className="mt-1 text-2xl font-bold text-amber-300">{techCount}</p>
        </div>
        <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-3">
          <span className="text-xs text-emerald-400 font-medium">Compliance Audits</span>
          <p className="mt-1 text-2xl font-bold text-emerald-400">{auditCount}</p>
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
      <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
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
                    <div className="font-semibold text-zinc-100">{rep.title}</div>
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
                      className={`rounded px-2 py-0.5 text-xs font-bold font-mono ${
                        rep.format === "PDF"
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

      {/* HTML Report Preview Modal */}
      {previewReport && (
        <Modal
          isOpen={Boolean(previewReport)}
          onClose={() => setPreviewReport(null)}
          title={`Preview: ${previewReport.title}`}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-zinc-400">
              <span>SHA-256 Digest: <code className="text-zinc-300">{previewReport.sha256Digest.slice(0, 24)}...</code></span>
              <Button size="sm" variant="secondary" onClick={() => handleDownload(previewReport)}>
                Download {previewReport.format}
              </Button>
            </div>

            {isPreviewLoading ? (
              <div className="h-96 flex items-center justify-center">
                <SkeletonLoader lines={6} />
              </div>
            ) : (
              <div className="h-[550px] w-full rounded-lg border border-zinc-800 overflow-hidden bg-zinc-950">
                <iframe
                  title={previewReport.title}
                  srcDoc={previewHtml}
                  sandbox="allow-same-origin"
                  className="w-full h-full border-0"
                />
              </div>
            )}

            <div className="flex justify-end">
              <Button variant="secondary" onClick={() => setPreviewReport(null)}>
                Close Preview
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
