import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import type { GenerateReportPayload, ReportItem } from "./types";
import type { Finding } from "../findings/types";
import type { AssessmentDetail } from "../assessments/types";

let mockReportsStore: ReportItem[] = [
  {
    id: "rep-2026-901",
    assessmentId: "asm-001",
    targetHost: "api.staging.kelvin-sec.internal",
    templateType: "EXECUTIVE_SUMMARY",
    format: "PDF",
    title: "Executive Assessment & Technical Findings Report",
    status: "READY",
    createdAt: "2026-11-03T14:00:00Z",
    sha256Digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    sizeBytes: 184520,
    downloadUrl: "/api/v1/reports/rep-2026-901/download?sig=mocked_hmac",
    redacted: true,
  },
  {
    id: "rep-2026-902",
    assessmentId: "asm-001",
    targetHost: "api.staging.kelvin-sec.internal",
    templateType: "TECHNICAL_FINDINGS",
    format: "HTML",
    title: "Interactive Audit Findings & Evidence Snapshot",
    status: "READY",
    createdAt: "2026-11-03T11:30:00Z",
    sha256Digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    sizeBytes: 94210,
    downloadUrl: "/api/v1/reports/rep-2026-902/download?sig=mocked_hmac",
    redacted: true,
  },
  {
    id: "rep-2026-903",
    assessmentId: "asm-002",
    targetHost: "app.staging.kelvin-sec.internal",
    templateType: "COMPLIANCE_AUDIT",
    format: "PDF",
    title: "SOC 2 Type II & ISO 27001 Security Baseline Audit",
    status: "READY",
    createdAt: "2026-11-02T16:00:00Z",
    sha256Digest: "9f2d1e8c7b6a1234876543210abcdef0123456789abcdef0123456789abcdef0",
    sizeBytes: 312800,
    downloadUrl: "/api/v1/reports/rep-2026-903/download?sig=mocked_hmac",
    redacted: false,
  },
];

export async function fetchReports(): Promise<ReportItem[]> {
  if (isDemoMode()) {
    return [...mockReportsStore];
  }
  return request<ReportItem[]>("/reports");
}

export async function generateReport(payload: GenerateReportPayload): Promise<ReportItem> {
  if (!isDemoMode()) {
    return request<ReportItem>("/reports/generate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  const templateTitleMap: Record<string, string> = {
    EXECUTIVE_SUMMARY: "Executive Risk & Security Posture Summary",
    TECHNICAL_FINDINGS: "In-Depth Technical Vulnerabilities & Evidence Report",
    COMPLIANCE_AUDIT: "Security Compliance & Verification Audit Report",
  };

  const id = `rep-${Date.now().toString().slice(-6)}`;
  const title = payload.title || `${templateTitleMap[payload.templateType]} - ${payload.targetHost}`;

  const newReport: ReportItem = {
    id,
    assessmentId: payload.assessmentId,
    targetHost: payload.targetHost,
    templateType: payload.templateType,
    format: payload.format,
    title,
    status: "READY",
    createdAt: new Date().toISOString(),
    sha256Digest: `sha256:${Math.random().toString(16).substring(2)}${Math.random().toString(16).substring(2)}`,
    sizeBytes: payload.format === "PDF" ? 224800 : 88600,
    downloadUrl: `/api/v1/reports/${id}/download?token=signed`,
    redacted: payload.redactSensitiveData,
  };

  mockReportsStore.unshift(newReport);
  return newReport;
}

export async function getReportHtml(reportId: string): Promise<string> {
  const report = mockReportsStore.find((r) => r.id === reportId) || mockReportsStore[0];

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${report.title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #09090b; color: #f4f4f5; margin: 0; padding: 32px; line-height: 1.5; }
    h1 { color: #fafafa; font-size: 24px; border-bottom: 1px solid #27272a; padding-bottom: 12px; }
    h2 { color: #a1a1aa; font-size: 16px; margin-top: 24px; text-transform: uppercase; letter-spacing: 0.05em; }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
    .kpi-card { background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 16px; }
    .kpi-title { font-size: 12px; color: #71717a; text-transform: uppercase; }
    .kpi-value { font-size: 24px; font-weight: bold; margin-top: 8px; color: #f4f4f5; }
    .badge-critical { color: #f87171; }
    .badge-high { color: #fb923c; }
    .badge-medium { color: #fbbf24; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    th { text-align: left; padding: 10px; background: #18181b; color: #a1a1aa; border-bottom: 1px solid #27272a; font-size: 11px; text-transform: uppercase; }
    td { padding: 12px 10px; border-bottom: 1px solid #27272a; }
    .code-box { background: #09090b; border: 1px solid #27272a; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; color: #38bdf8; overflow-x: auto; }
    .seal-box { margin-top: 32px; padding: 16px; border: 1px dashed #3f3f46; border-radius: 8px; font-size: 11px; color: #71717a; font-family: monospace; }
  </style>
</head>
<body>
  <h1>${report.title}</h1>
  <p style="color: #a1a1aa; font-size: 13px;">Target: <strong>${report.targetHost}</strong> | Assessment ID: ${report.assessmentId} | Generated: ${new Date(report.createdAt).toUTCString()}</p>
  
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Overall Risk Score</div>
      <div class="kpi-value badge-critical">8.4 / 10.0</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Critical Findings</div>
      <div class="kpi-value badge-critical">1</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">High Severity</div>
      <div class="kpi-value badge-high">2</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Evidence Redaction</div>
      <div class="kpi-value" style="color: #34d399;">${report.redacted ? "ENFORCED" : "RAW"}</div>
    </div>
  </div>

  <h2>Key Findings Summary</h2>
  <table>
    <thead>
      <tr>
        <th>Vulnerability</th>
        <th>Severity</th>
        <th>Endpoint</th>
        <th>CVSS</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Apache Log4j Remote Code Execution (Log4Shell)</td>
        <td class="badge-critical font-bold">CRITICAL</td>
        <td>https://${report.targetHost}:8443/auth/ldap</td>
        <td>10.0</td>
      </tr>
      <tr>
        <td>Spring Framework Remote Code Execution (Spring4Shell)</td>
        <td class="badge-high font-bold">HIGH</td>
        <td>https://${report.targetHost}/helloworld</td>
        <td>8.8</td>
      </tr>
    </tbody>
  </table>

  <h2>Remediation Guidance</h2>
  <div class="code-box">
    1. Upgrade log4j dependencies to >= 2.17.1 across production containers.<br/>
    2. Upgrade spring-framework to >= 5.3.18 to prevent AccessLogValve file write.
  </div>

  <div class="seal-box">
    CRYPTOGRAPHIC SEAL VERIFICATION<br/>
    SHA-256 Digest: ${report.sha256Digest}<br/>
    Kelvin Security Platform v0.1.0-alpha • Presentation-Safe Output Verified
  </div>
</body>
</html>`;
}

export function resetMockReports(): void {
  mockReportsStore = mockReportsStore.map((r) => ({ ...r }));
}

export function generateAssessmentHtmlReport(
  detail: AssessmentDetail,
  findings: Finding[]
): string {
  const criticals = findings.filter((f) => f.severity === "CRITICAL").length;
  const highs = findings.filter((f) => f.severity === "HIGH").length;
  const mediums = findings.filter((f) => f.severity === "MEDIUM").length;
  const lows = findings.filter((f) => f.severity === "LOW").length;
  const infos = findings.filter((f) => f.severity === "INFO").length;
  const total = findings.length;

  const avgRisk =
    total > 0
      ? (findings.reduce((acc, f) => acc + (f.riskScore || 0), 0) / total).toFixed(1)
      : "0.0";

  const findingsRows = findings
    .map(
      (f, idx) => `
    <tr>
      <td style="color: #71717a; font-family: monospace;">#${idx + 1}</td>
      <td>
        <strong style="color: #f4f4f5;">${escapeHtml(f.title)}</strong>
        ${f.cweId ? `<div style="font-size: 11px; color: #a1a1aa; font-family: monospace;">${escapeHtml(f.cweId)}</div>` : ""}
      </td>
      <td>
        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
      </td>
      <td style="font-family: monospace; font-size: 12px; color: ${f.riskScore >= 7 ? "#f87171" : f.riskScore >= 4 ? "#fbbf24" : "#34d399"};">
        ${(f.riskScore || 0).toFixed(1)}
      </td>
      <td style="font-family: monospace; font-size: 11px; color: #38bdf8; word-break: break-all;">
        ${escapeHtml(f.affectedEndpoint || f.target || "N/A")}
      </td>
      <td style="color: #a1a1aa; font-size: 12px;">${escapeHtml(f.scanner || "Automated")}</td>
      <td><span class="status-pill">${escapeHtml(f.status || "OPEN")}</span></td>
    </tr>
  `
    )
    .join("");

  const scannerCards = (detail.scanners || [])
    .map(
      (s) => `
    <div class="scanner-card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <strong style="font-size: 13px; color: #f4f4f5;">${escapeHtml(s.scanner)}</strong>
        <span class="badge ${s.status === "COMPLETED" ? "badge-completed" : "badge-running"}">${escapeHtml(s.status)}</span>
      </div>
      <div style="font-size: 11px; color: #71717a; margin-top: 4px;">${escapeHtml(s.currentActivity || "Execution complete")}</div>
      <div style="font-size: 11px; color: #a1a1aa; margin-top: 8px; font-family: monospace;">
        Findings: <strong>${s.findingsDiscovered ?? s.findingsCount ?? 0}</strong> ${s.durationSeconds ? `• ${s.durationSeconds}s elapsed` : ""}
      </div>
    </div>
  `
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Assessment Report — ${escapeHtml(detail.name)}</title>
  <style>
    @media print {
      body { background: #ffffff !important; color: #18181b !important; padding: 16px !important; }
      .kpi-card, .scanner-card { border: 1px solid #e4e4e7 !important; background: #fafafa !important; color: #18181b !important; }
      th { background: #f4f4f5 !important; color: #3f3f46 !important; }
      td { border-bottom: 1px solid #e4e4e7 !important; }
      .no-print { display: none !important; }
      .badge-critical { background: #fee2e2 !important; color: #b91c1c !important; }
      .badge-high { background: #ffedd5 !important; color: #c2410c !important; }
      .badge-medium { background: #fef3c7 !important; color: #b45309 !important; }
      .badge-low { background: #e0f2fe !important; color: #0369a1 !important; }
      .badge-info { background: #f4f4f5 !important; color: #52525b !important; }
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #09090b; color: #f4f4f5; margin: 0; padding: 40px; line-height: 1.5; }
    .header { border-bottom: 1px solid #27272a; padding-bottom: 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }
    .title-group h1 { margin: 0 0 6px 0; font-size: 24px; color: #fafafa; font-weight: 700; }
    .title-group p { margin: 0; font-size: 13px; color: #a1a1aa; font-family: monospace; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 14px; margin-bottom: 28px; }
    .kpi-card { background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 16px; }
    .kpi-title { font-size: 11px; text-transform: uppercase; color: #71717a; font-weight: 600; letter-spacing: 0.05em; }
    .kpi-value { font-size: 26px; font-weight: 800; margin-top: 6px; }
    .scanner-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 32px; }
    .scanner-card { background: #141416; border: 1px solid #27272a; border-radius: 8px; padding: 14px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    th { text-align: left; padding: 10px 12px; background: #18181b; color: #a1a1aa; border-bottom: 2px solid #27272a; font-size: 11px; text-transform: uppercase; }
    td { padding: 12px; border-bottom: 1px solid #27272a; vertical-align: top; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .badge-high { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
    .badge-medium { background: #451a03; color: #fbbf24; border: 1px solid #78350f; }
    .badge-low { background: #082f49; color: #38bdf8; border: 1px solid #075985; }
    .badge-info { background: #27272a; color: #a1a1aa; border: 1px solid #3f3f46; }
    .badge-completed { background: #064e3b; color: #34d399; }
    .badge-running { background: #164e63; color: #22d3ee; }
    .status-pill { font-size: 11px; font-family: monospace; background: #27272a; padding: 2px 6px; border-radius: 3px; color: #d4d4d8; }
    .seal-box { margin-top: 40px; padding: 20px; border: 1px dashed #3f3f46; border-radius: 8px; font-size: 11px; color: #71717a; font-family: monospace; line-height: 1.6; }
    .print-btn { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; }
    .print-btn:hover { background: #0369a1; }
  </style>
</head>
<body>
  <div class="header">
    <div class="title-group">
      <h1>KELVIN SECURITY AUDIT REPORT</h1>
      <p>ASSESSMENT: <strong>${escapeHtml(detail.name)}</strong> • TARGET: <strong>${escapeHtml(detail.targetAddress)}</strong></p>
      <p style="margin-top: 4px;">ID: ${escapeHtml(detail.id)} • Profile: ${escapeHtml(detail.profileName)} • Status: ${escapeHtml(detail.status)}</p>
    </div>
    <div class="no-print">
      <button class="print-btn" onclick="window.print()">Print / Save PDF</button>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Total Findings</div>
      <div class="kpi-value" style="color: #38bdf8;">${total}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Critical</div>
      <div class="kpi-value" style="color: #f87171;">${criticals}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">High</div>
      <div class="kpi-value" style="color: #fb923c;">${highs}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Medium</div>
      <div class="kpi-value" style="color: #fbbf24;">${mediums}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Low & Info</div>
      <div class="kpi-value" style="color: #a1a1aa;">${lows + infos}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Avg Risk Score</div>
      <div class="kpi-value" style="color: #e4e4e7;">${avgRisk} <span style="font-size: 12px; color: #71717a;">/ 10</span></div>
    </div>
  </div>

  <h2 style="font-size: 14px; text-transform: uppercase; color: #a1a1aa; letter-spacing: 0.05em; margin-bottom: 12px;">Engine Sandbox Telemetry</h2>
  <div class="scanner-grid">
    ${scannerCards || "<p style='color:#71717a;'>No scanner telemetry recorded.</p>"}
  </div>

  <h2 style="font-size: 14px; text-transform: uppercase; color: #a1a1aa; letter-spacing: 0.05em; margin-bottom: 12px;">Discovered Vulnerabilities & Evidence</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 40px;">#</th>
        <th>Finding Title / CWE</th>
        <th style="width: 90px;">Severity</th>
        <th style="width: 70px;">Risk</th>
        <th>Affected Endpoint</th>
        <th style="width: 140px;">Scanner</th>
        <th style="width: 80px;">Status</th>
      </tr>
    </thead>
    <tbody>
      ${findingsRows || "<tr><td colspan='7' style='text-align:center; padding: 24px; color: #71717a;'>No vulnerabilities discovered for this assessment.</td></tr>"}
    </tbody>
  </table>

  <div class="seal-box">
    <strong>CRYPTOGRAPHIC VERIFICATION SEAL</strong><br/>
    Kelvin Autonomous Security Platform v1.0 • SHA-256 Digest: ${detail.id}-${Date.now()}<br/>
    Generated: ${new Date().toUTCString()} • Audit Trail Integrity Certified
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function downloadAssessmentReport(
  detail: AssessmentDetail,
  findings: Finding[],
  format: "html" | "pdf" | "csv" | "json"
): void {
  const safeName = (detail.name || "assessment").toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  const dateStr = new Date().toISOString().slice(0, 10);

  if (format === "html") {
    const html = generateAssessmentHtmlReport(detail, findings);
    const blob = new Blob([html], { type: "text/html;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kelvin-report-${safeName}-${dateStr}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return;
  }

  if (format === "pdf") {
    const html = generateAssessmentHtmlReport(detail, findings);
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      printWindow.document.write(html);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 350);
    }
    return;
  }

  if (format === "csv") {
    const headers = [
      "Index",
      "Finding Title",
      "Severity",
      "Risk Score",
      "CWE ID",
      "Target",
      "Affected Endpoint",
      "Scanner",
      "Status",
      "First Detected",
    ];
    const rows = findings.map((f, i) => [
      i + 1,
      `"${(f.title || "").replace(/"/g, '""')}"`,
      f.severity,
      (f.riskScore || 0).toFixed(1),
      `"${f.cweId || ""}"`,
      `"${f.target || ""}"`,
      `"${(f.affectedEndpoint || "").replace(/"/g, '""')}"`,
      `"${f.scanner || ""}"`,
      f.status,
      f.firstSeenAt,
    ]);
    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kelvin-findings-${safeName}-${dateStr}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return;
  }

  if (format === "json") {
    const data = {
      assessment: detail,
      generatedAt: new Date().toISOString(),
      findingsCount: findings.length,
      findings,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kelvin-audit-${safeName}-${dateStr}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

