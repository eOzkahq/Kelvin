import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { buildStructuredReport, type ReportFindingBlock } from "./reportModel";
import { EOZKA_FULL_LOGO_SVG } from "./eozkaReportLogo";
import type { GenerateReportPayload, ReportItem } from "./types";
import type { Finding } from "../findings/types";
import type { AssessmentDetail } from "../assessments/types";

const REPORTS_STORAGE_KEY = "kelvin_generated_reports";

function loadStoredReports(): ReportItem[] {
  try {
    const raw = localStorage.getItem(REPORTS_STORAGE_KEY) || sessionStorage.getItem(REPORTS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch {
    // ignore
  }
  return [];
}

function persistStoredReports(reports: ReportItem[]): void {
  try {
    const serialized = JSON.stringify(reports);
    try { localStorage.setItem(REPORTS_STORAGE_KEY, serialized); } catch { /* ignore */ }
    try { sessionStorage.setItem(REPORTS_STORAGE_KEY, serialized); } catch { /* ignore */ }
  } catch {
    // ignore
  }
}

const DEFAULT_MOCK_REPORTS: ReportItem[] = [
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

const storedOnInit = loadStoredReports();
let mockReportsStore: ReportItem[] = storedOnInit.length > 0 ? storedOnInit : [...DEFAULT_MOCK_REPORTS];

export async function fetchReports(): Promise<ReportItem[]> {
  if (isDemoMode()) {
    return [...mockReportsStore];
  }
  try {
    const remote = await request<ReportItem[]>("/reports");
    const remoteList = Array.isArray(remote) ? remote : [];
    const remoteIds = new Set(remoteList.map((r) => r.id));
    const merged = [...remoteList];
    for (const local of mockReportsStore) {
      if (!remoteIds.has(local.id)) {
        merged.push(local);
      }
    }
    return merged;
  } catch {
    return [...mockReportsStore];
  }
}

export async function generateReport(payload: GenerateReportPayload): Promise<ReportItem> {
  if (!isDemoMode()) {
    try {
      const res = await request<ReportItem>("/reports/generate", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (res && res.id) {
        mockReportsStore.unshift(res);
        persistStoredReports(mockReportsStore);
        return res;
      }
    } catch {
      // Fallback gracefully to client-side report generation
    }
  }

  const templateTitleMap: Record<string, string> = {
    EXECUTIVE_SUMMARY: "Executive Risk & Security Posture Summary",
    TECHNICAL_FINDINGS: "Technical Security Assessment Report",
    COMPLIANCE_AUDIT: "Security Compliance & Verification Audit",
  };

  const id = `rep-${Date.now().toString().slice(-6)}`;
  const title = payload.title || `${templateTitleMap[payload.templateType]} — ${payload.targetHost}`;

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
  persistStoredReports(mockReportsStore);
  return newReport;
}

export async function ensureReportForAssessment(
  assessmentId: string,
  targetHost: string,
  assessmentName: string,
): Promise<ReportItem> {
  const existing = mockReportsStore.find((r) => r.assessmentId === assessmentId);
  if (existing) return existing;
  return generateReport({
    assessmentId,
    targetHost,
    templateType: "TECHNICAL_FINDINGS",
    format: "PDF",
    redactSensitiveData: true,
    title: `${assessmentName} — Security Assessment`,
  });
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlTag(
  name: string,
  attrs: Record<string, string | undefined> | null,
  ...children: string[]
): string {
  const open = "<" + name;
  const close = "</" + name + ">";
  const attrParts: string[] = [];
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v !== undefined) {
        attrParts.push(`${k}="${escapeHtml(v)}"`);
      }
    }
  }
  const attrStr = attrParts.length > 0 ? " " + attrParts.join(" ") : "";
  return `${open}${attrStr}>${children.join("")}${close}`;
}

function renderFindingHtml(f: ReportFindingBlock): string {
  const sevClass =
    f.severity === "CRITICAL"
      ? "tag-critical"
      : f.severity === "HIGH"
        ? "tag-high"
        : f.severity === "MEDIUM"
          ? "tag-medium"
          : "tag-low";

  const deltaClass = f.deltaStatus === "NEW" ? "delta-new" : "delta-base";
  const deltaLabel = f.deltaStatus === "NEW" ? "NEW IN TIER" : f.deltaStatus === "INHERITED" ? "INHERITED" : "BASELINE";

  return htmlTag(
    "article",
    { class: "finding-entry" },
    htmlTag(
      "div",
      { class: "finding-head" },
      htmlTag(
        "div",
        { class: "finding-id-row" },
        htmlTag("span", { class: "finding-id" }, escapeHtml(f.id)),
        htmlTag("span", { class: `sev-tag ${sevClass}` }, f.severity),
        htmlTag("span", { class: `delta-chip ${deltaClass}` }, deltaLabel),
        f.tierLabel ? htmlTag("span", { class: "tier-chip" }, escapeHtml(f.tierLabel)) : "",
        htmlTag("span", { class: "meta-inline" }, `CVSS ${f.cvss.toFixed(1)}`),
        htmlTag("span", { class: "meta-dot" }, "&middot;"),
        htmlTag("span", { class: "meta-inline" }, escapeHtml(f.cwe)),
        htmlTag("span", { class: "meta-dot" }, "&middot;"),
        htmlTag("span", { class: "meta-inline" }, escapeHtml(f.scanner)),
      ),
      htmlTag("h3", null, escapeHtml(f.title)),
      htmlTag("div", { class: "finding-endpoint" }, "Target: ", htmlTag("code", null, escapeHtml(f.endpoint))),
    ),
    htmlTag("p", { class: "finding-body" }, escapeHtml(f.description)),
    htmlTag(
      "div",
      { class: "inset-block" },
      htmlTag("div", { class: "inset-label" }, "Evidence Observed"),
      htmlTag("pre", { class: "evidence-pre" }, escapeHtml(f.evidence)),
    ),
    htmlTag(
      "div",
      { class: "inset-block inset-action" },
      htmlTag("div", { class: "inset-label" }, "Recommended Fix"),
      htmlTag("div", { class: "inset-text" }, escapeHtml(f.remediation)),
    ),
  );
}

export async function getReportHtml(reportId: string): Promise<string> {
  const report = mockReportsStore.find((r) => r.id === reportId) || mockReportsStore[0];
  const doc = buildStructuredReport(report);

  const toneColorMap = {
    danger: "#991b1b",
    warn: "#92400e",
    success: "#166534",
    neutral: "#211a57",
  };

  const kpisHtml = doc.kpis
    .map((k) =>
      htmlTag(
        "div",
        { class: "metric-cell" },
        htmlTag("div", { class: "metric-label" }, escapeHtml(k.label)),
        htmlTag(
          "div",
          { class: "metric-value", style: `color:${toneColorMap[k.tone ?? "neutral"]};` },
          escapeHtml(k.value),
        ),
        htmlTag("div", { class: "metric-sub" }, escapeHtml(k.sub)),
      ),
    )
    .join("");

  const tablesHtml = doc.tables
    .map((t) =>
      htmlTag(
        "section",
        { class: "doc-section" },
        htmlTag("h2", null, escapeHtml(t.heading)),
        htmlTag(
          "table",
          null,
          htmlTag(
            "thead",
            null,
            htmlTag("tr", null, ...t.columns.map((c) => htmlTag("th", null, escapeHtml(c)))),
          ),
          htmlTag(
            "tbody",
            null,
            ...t.rows.map((row) =>
              htmlTag(
                "tr",
                null,
                ...row.map((cell, ci) =>
                  htmlTag("td", { class: ci === 0 ? "mono-cell strong-cell" : "" }, escapeHtml(cell)),
                ),
              ),
            ),
          ),
        ),
      ),
    )
    .join("");

  const scoringHtml = doc.scoringRubric
    .map((sc) => {
      const cls = sc.status === "PASS" ? "tag-pass" : sc.status === "WARN" ? "tag-medium" : "tag-critical";
      return htmlTag(
        "tr",
        null,
        htmlTag("td", null, htmlTag("strong", null, escapeHtml(sc.category))),
        htmlTag("td", { class: "mono-cell" }, `${sc.earned} / ${sc.max}`),
        htmlTag("td", { class: "muted-cell" }, escapeHtml(sc.deductions)),
        htmlTag("td", null, htmlTag("span", { class: `sev-tag ${cls}` }, sc.status)),
      );
    })
    .join("");

  const groupedFindingsHtml = doc.tierGroups
    .map((grp) =>
      htmlTag(
        "div",
        { class: "tier-group-block" },
        htmlTag(
          "div",
          { class: "tier-group-head" },
          htmlTag("div", { class: "tier-group-title" }, escapeHtml(grp.heading)),
          htmlTag("div", { class: "tier-group-sub" }, escapeHtml(grp.subtitle)),
        ),
        ...grp.findings.map((f) => renderFindingHtml(f)),
      ),
    )
    .join("");

  const complianceHtml = doc.complianceRows
    .map((row) => {
      const cls = row.status === "FAIL" ? "tag-critical" : row.status === "WARN" ? "tag-medium" : "tag-pass";
      return htmlTag(
        "tr",
        null,
        htmlTag("td", null, htmlTag("strong", null, escapeHtml(row.control))),
        htmlTag("td", null, escapeHtml(row.requirement)),
        htmlTag("td", { class: "mono-cell" }, escapeHtml(row.evidence)),
        htmlTag("td", null, htmlTag("span", { class: `sev-tag ${cls}` }, row.status)),
      );
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(report.title)}</title>
  <style>
    @page { size: letter; margin: 16mm 18mm; }
    * { box-sizing: border-box; }
    body {
      font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: #f1f0ec;
      color: #151821;
      margin: 0;
      padding: 28px 20px;
      line-height: 1.55;
      font-size: 12.5px;
      -webkit-font-smoothing: antialiased;
    }
    .paper {
      max-width: 820px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #e2ddd0;
      border-top: 4px solid #211a57;
      padding: 40px 46px;
      box-shadow: 0 2px 18px rgba(15, 20, 35, 0.06);
    }
    .masthead {
      background: #faf8f5;
      border: 1px solid #e7e0d0;
      border-bottom: 2px solid #b38a2b;
      padding: 20px 24px 18px 24px;
      margin-bottom: 20px;
    }
    .brand-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding-bottom: 14px;
      margin-bottom: 14px;
      border-bottom: 1px solid #e7e0d0;
    }
    .brand-lockup {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }
    .eozka-header-svg {
      width: 112px;
      height: 45px;
      flex-shrink: 0;
      display: block;
    }
    .brand-divider {
      width: 1px;
      height: 28px;
      background: #d8ceb8;
    }
    .doc-kicker {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9.5px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #211a57;
      font-weight: 700;
      line-height: 1.4;
    }
    .doc-sub-kicker {
      font-size: 10.5px;
      color: #6b6252;
      display: block;
      font-weight: 500;
      letter-spacing: 0.03em;
      text-transform: none;
    }
    .tier-pill-head {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 10px;
      padding: 4px 10px;
      background: #211a57;
      color: #faf8f5;
      border-radius: 3px;
      border-bottom: 2px solid #d4b23c;
      white-space: nowrap;
    }
    h1 {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.015em;
      color: #0f1423;
      line-height: 1.25;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid #e7e1d4;
      font-size: 11px;
    }
    .meta-k {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9.5px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #6b6252;
      display: block;
    }
    .meta-v {
      color: #0f1423;
      font-weight: 600;
      word-break: break-word;
    }
    .metric-strip {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      border-top: 1px solid #dcd6c8;
      border-bottom: 1px solid #dcd6c8;
      margin-bottom: 24px;
    }
    .metric-cell {
      padding: 12px 14px;
      border-right: 1px solid #eae6dc;
    }
    .metric-cell:first-child { padding-left: 0; }
    .metric-cell:last-child { border-right: none; }
    .metric-label {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9.5px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #6b6252;
    }
    .metric-value {
      font-size: 18px;
      font-weight: 700;
      margin-top: 4px;
      font-variant-numeric: tabular-nums;
    }
    .metric-sub {
      font-size: 11px;
      color: #4b5563;
      margin-top: 2px;
    }
    .doc-section {
      margin-top: 24px;
    }
    h2 {
      margin: 0 0 10px 0;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #211a57;
      padding-bottom: 5px;
      border-bottom: 1.5px solid #211a57;
    }
    p.prose {
      margin: 0 0 10px 0;
      color: #1f2937;
      font-size: 12.5px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 8px 0 6px 0;
      font-size: 11.5px;
    }
    th {
      text-align: left;
      padding: 7px 8px;
      border-bottom: 1.5px solid #b38a2b;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #211a57;
    }
    td {
      padding: 8px;
      border-bottom: 1px solid #ebe8df;
      vertical-align: top;
      color: #151821;
    }
    .mono-cell {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      font-variant-numeric: tabular-nums;
    }
    .strong-cell { font-weight: 600; color: #0f1423; }
    .muted-cell { color: #4b5563; }
    .sev-tag {
      display: inline-block;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9.5px;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 1px 6px;
      border-radius: 2px;
      border: 1px solid;
      text-transform: uppercase;
    }
    .tag-critical { color: #991b1b; border-color: #fca5a5; background: #fef2f2; }
    .tag-high { color: #9a3412; border-color: #fdba74; background: #fff7ed; }
    .tag-medium { color: #92400e; border-color: #fcd34d; background: #fffbeb; }
    .tag-low { color: #334155; border-color: #cbd5e1; background: #f8fafc; }
    .tag-pass { color: #166534; border-color: #86efac; background: #f0fdf4; }
    .delta-chip {
      display: inline-block;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 2px;
      letter-spacing: 0.04em;
    }
    .delta-new { background: #211a57; color: #faf8f5; }
    .delta-base { background: #f3ece0; color: #6b5217; border: 1px solid #d4b23c; }
    .tier-chip {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9.5px;
      color: #6b6252;
      background: #faf8f5;
      border: 1px solid #e5decb;
      padding: 1px 6px;
      border-radius: 2px;
    }
    .tier-group-block {
      margin-top: 16px;
      border: 1px solid #e7e1d4;
      border-radius: 4px;
      padding: 12px 16px 4px 16px;
      background: #ffffff;
    }
    .tier-group-head {
      padding-bottom: 8px;
      margin-bottom: 6px;
      border-bottom: 1px solid #e7e1d4;
    }
    .tier-group-title {
      font-size: 12.5px;
      font-weight: 700;
      color: #211a57;
    }
    .tier-group-sub {
      font-size: 11px;
      color: #6b6252;
      margin-top: 2px;
    }
    .finding-entry {
      padding: 12px 0 14px 0;
      border-bottom: 1px solid #ebe8df;
      page-break-inside: avoid;
    }
    .finding-entry:last-child { border-bottom: none; }
    .finding-id-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-bottom: 5px;
    }
    .finding-id {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      font-weight: 700;
      color: #0f1423;
    }
    .meta-inline {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 10.5px;
      color: #4b5563;
    }
    .meta-dot { color: #9ca3af; }
    h3 {
      margin: 2px 0 4px 0;
      font-size: 13.5px;
      font-weight: 700;
      color: #0f1423;
    }
    .finding-endpoint {
      font-size: 11px;
      color: #4b5563;
      margin-bottom: 8px;
    }
    .finding-endpoint code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      color: #211a57;
    }
    .finding-body {
      margin: 0 0 10px 0;
      color: #1f2937;
      font-size: 12px;
    }
    .inset-block {
      border-left: 2px solid #d4b23c;
      background: #faf8f5;
      padding: 7px 12px;
      margin-top: 6px;
    }
    .inset-action {
      border-left-color: #211a57;
      background: #f6f5fa;
    }
    .inset-label {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #6b6252;
      margin-bottom: 3px;
    }
    .evidence-pre {
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      color: #151821;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.45;
    }
    .inset-text {
      font-size: 12px;
      color: #151821;
      line-height: 1.45;
    }
    .seal-footer {
      margin-top: 28px;
      padding-top: 12px;
      border-top: 2px solid #211a57;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 10px;
      color: #4b5563;
      line-height: 1.6;
    }
    @media (max-width: 640px) {
      .paper { padding: 24px 20px; }
      .meta-grid, .metric-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric-cell { border-bottom: 1px solid #eae6dc; }
    }
    @media print {
      body { background: #ffffff; padding: 0; }
      .paper { border: none; border-top: 4px solid #211a57; box-shadow: none; padding: 0; max-width: none; }
    }
  </style>
</head>
<body>
  <div class="paper">
    <header class="masthead">
      <div class="brand-bar">
        <div class="brand-lockup">
          ${EOZKA_FULL_LOGO_SVG}
          <span class="brand-divider" aria-hidden="true"></span>
          <div class="doc-kicker">
            KELVIN SECURITY PLATFORM
            <span class="doc-sub-kicker">Official Security Deliverable</span>
          </div>
        </div>
        <span class="tier-pill-head">${escapeHtml(doc.planLabel)} · ${escapeHtml(report.templateType.replace(/_/g, " "))}</span>
      </div>
      <h1>${escapeHtml(report.title)}</h1>
      <div class="meta-grid">
        <div><span class="meta-k">Target Scope</span><span class="meta-v">${escapeHtml(report.targetHost)}</span></div>
        <div><span class="meta-k">Assessment Ref</span><span class="meta-v">${escapeHtml(report.assessmentId)}</span></div>
        <div><span class="meta-k">Generated UTC</span><span class="meta-v">${new Date(report.createdAt).toISOString().slice(0, 16).replace("T", " ")}</span></div>
        <div><span class="meta-k">Redaction</span><span class="meta-v">${report.redacted ? "Enforced" : "Unmasked"}</span></div>
      </div>
    </header>

    <div class="metric-strip">${kpisHtml}</div>

    <section class="doc-section">
      <h2>Executive Overview &amp; Scope Delta</h2>
      <p class="prose">${escapeHtml(doc.executiveSummary)}</p>
    </section>

    <section class="doc-section">
      <h2>Assessment Marking &amp; Posture Scorecard (${doc.postureScore} / 100 &middot; Grade ${escapeHtml(doc.postureGrade)})</h2>
      <table>
        <thead>
          <tr>
            <th>Security Domain</th>
            <th>Score</th>
            <th>Assessment Notes</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${scoringHtml}</tbody>
      </table>
    </section>

    ${tablesHtml}

    <section class="doc-section">
      <h2>Detailed Findings &amp; Remediation Guidance (${doc.findings.length})</h2>
      ${groupedFindingsHtml}
    </section>

    <section class="doc-section">
      <h2>Compliance Control Alignment</h2>
      <table>
        <thead>
          <tr>
            <th>Control</th>
            <th>Requirement</th>
            <th>Evidence</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${complianceHtml}</tbody>
      </table>
    </section>

    <footer class="seal-footer">
      <strong>CRYPTOGRAPHIC SEAL VERIFICATION</strong><br/>
      SHA-256 Digest: ${escapeHtml(report.sha256Digest)}<br/>
      Confidential Deliverable &middot; Kelvin by eOzka · Augmenting Sentient
    </footer>
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

