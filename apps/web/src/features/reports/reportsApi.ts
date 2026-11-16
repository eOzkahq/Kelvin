import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import type { GenerateReportPayload, ReportItem } from "./types";

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
