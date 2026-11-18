import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { buildStructuredReport, type ReportFindingBlock } from "./reportModel";
import { EOZKA_FULL_LOGO_SVG } from "./eozkaReportLogo";
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
