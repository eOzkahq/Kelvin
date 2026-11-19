import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchReports,
  generateReport,
  getReportHtml,
  resetMockReports,
} from "./reportsApi";

describe("Assessment Reports & PDF Viewer (FE-12)", () => {
  beforeEach(() => {
    resetMockReports();
  });

  it("retrieves previously generated reports inventory", async () => {
    const reports = await fetchReports();
    expect(reports).toBeDefined();
    expect(reports.length).toBeGreaterThan(0);

    const first = reports[0];
    expect(first.title).toBeDefined();
    expect(first.targetHost).toBeDefined();
    expect(first.format).toBeDefined();
    expect(first.sha256Digest).toBeDefined();
    expect(first.sizeBytes).toBeGreaterThan(0);
  });

  it("generates an Executive Summary PDF report with evidence redaction", async () => {
    const newReport = await generateReport({
      assessmentId: "asm-sweep-09",
      targetHost: "gateway.prod.kelvin-sec.internal",
      templateType: "EXECUTIVE_SUMMARY",
      format: "PDF",
      redactSensitiveData: true,
    });

    expect(newReport.id).toBeDefined();
    expect(newReport.status).toBe("READY");
    expect(newReport.format).toBe("PDF");
    expect(newReport.redacted).toBe(true);
    expect(newReport.sha256Digest).toBeDefined();
  });

  it("generates an Interactive HTML Compliance Audit report", async () => {
    const newReport = await generateReport({
      assessmentId: "asm-compliance-01",
      targetHost: "auth.prod.kelvin-sec.internal",
      templateType: "COMPLIANCE_AUDIT",
      format: "HTML",
      redactSensitiveData: false,
      title: "Quarterly ISO 27001 Security Audit",
    });

    expect(newReport.title).toBe("Quarterly ISO 27001 Security Audit");
    expect(newReport.format).toBe("HTML");
    expect(newReport.templateType).toBe("COMPLIANCE_AUDIT");
  });

  it("renders report HTML containing KPI summaries, tier segregation, and cryptographic seal", async () => {
    const html = await getReportHtml("rep-2026-901");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Overall Risk Score");
    expect(html).toContain("CRYPTOGRAPHIC SEAL VERIFICATION");
    expect(html).toContain("Remediation Guidance");
    expect(html).toContain("Assessment Marking &amp; Posture Scorecard");
    expect(html).toContain("Tier Scope Segregation");
    expect(html).toContain("eOzka");
    expect(html).toContain("eozka-header-svg");
    expect(html).toContain("Augmenting Sentient");
    expect(html).not.toMatch(/<\s+[a-zA-Z]/);
    expect(html).not.toMatch(/&\s+[a-zA-Z]+;/);

    const techHtml = await getReportHtml("rep-2026-902");
    expect(techHtml).toContain("NEW IN TIER");
    expect(techHtml).toContain("INHERITED");
    expect(techHtml).toContain("Plan 2 — Extended Web DAST");
  });

  it("strictly enforces planwise bifurcations across Plan 1, Plan 2, and Plan 3", async () => {
    const { saveLiveScanResult } = await import("./liveScanStore");
    const { buildStructuredReport } = await import("./reportModel");
    const { buildSecurityReportPdfBlob } = await import("./pdfGenerator");

    const sampleFindings = [
      {
        id: "LIVE-001",
        title: "Missing DMARC DNS Policy Record",
        severity: "LOW" as const,
        cvss: 3.1,
        cwe: "CWE-290",
        endpoint: "_dmarc.youtube.com",
        scanner: "Custom-Workers",
        description: "No valid DMARC TXT record found.",
        evidence: "DNS TXT query returned NXDOMAIN.",
        remediation: "Publish DMARC TXT record.",
      },
      {
        id: "LIVE-002",
        title: "Missing Sender Policy Framework (SPF) DNS Record",
        severity: "LOW" as const,
        cvss: 3.1,
        cwe: "CWE-290",
        endpoint: "youtube.com",
        scanner: "Custom-Workers",
        description: "Domain lacks SPF record.",
        evidence: "No v=spf1 configured.",
        remediation: "Publish SPF TXT record.",
      },
      {
        id: "LIVE-003",
        title: "Missing DNS CAA Certificate Issuance Policy",
        severity: "INFO" as const,
        cvss: 2.3,
        cwe: "CWE-295",
        endpoint: "youtube.com",
        scanner: "Custom-Workers",
        description: "No CAA record found.",
        evidence: "CAA query returned 0 records.",
        remediation: "Publish DNS CAA record.",
      },
      {
        id: "LIVE-004",
        title: "Server Technology Stack Fingerprint Disclosed",
        severity: "INFO" as const,
        cvss: 2.0,
        cwe: "CWE-200",
        endpoint: "https://youtube.com/",
        scanner: "http-headers",
        description: "Server header exposed.",
        evidence: "Server: ESF",
        remediation: "Strip server banners.",
      },
      {
        id: "LIVE-005",
        title: "Missing Referrer-Policy Header",
        severity: "LOW" as const,
        cvss: 2.6,
        cwe: "CWE-200",
        endpoint: "https://youtube.com/",
        scanner: "OWASP-ZAP",
        description: "Referrer-Policy header is absent.",
        evidence: "Observed referrer-policy: <not set>",
        remediation: "Configure Referrer-Policy.",
      },
      {
        id: "LIVE-006",
        title: "Third-Party JavaScript Loaded Without Subresource Integrity (9 scripts)",
        severity: "MEDIUM" as const,
        cvss: 4.9,
        cwe: "CWE-353",
        endpoint: "https://youtube.com/",
        scanner: "Trivy",
        description: "External CDN scripts lack SRI.",
        evidence: "9 scripts lack integrity attribute.",
        remediation: "Pin third-party scripts with SRI.",
      },
      {
        id: "LIVE-007",
        title: "Incomplete Cross-Origin Isolation Headers (COOP / CORP)",
        severity: "INFO" as const,
        cvss: 2.6,
        cwe: "CWE-346",
        endpoint: "https://youtube.com/",
        scanner: "Custom-Workers",
        description: "Missing COOP/CORP.",
        evidence: "COOP: same-origin-allow-popups",
        remediation: "Send COOP and CORP headers.",
      },
      {
        id: "LIVE-008",
        title: "HSTS Policy Lacks includeSubDomains or Preload Directive",
        severity: "LOW" as const,
        cvss: 3.2,
        cwe: "CWE-523",
        endpoint: "https://youtube.com/",
        scanner: "Custom-Workers",
        description: "HSTS lacks preload.",
        evidence: "Observed Strict-Transport-Security: max-age=31536000",
        remediation: "Add includeSubDomains and preload.",
      },
    ];

    const baseProbe = {
      targetUrl: "https://youtube.com/",
      hostname: "youtube.com",
      resolvedIps: ["142.250.195.46"],
      httpStatus: 200,
      latencyMs: 808,
      redirectsToHttps: true,
      tls: {
        supported: true,
        protocol: "TLSv1.3",
        cipher: "TLS_AES_256_GCM_SHA384",
        issuer: "Google Trust Services",
        validTo: "Jan 26 2027",
        daysRemaining: 68,
      },
      headers: {
        "accept-ch": "Sec-CH-Viewport-Width",
        "alt-svc": "h3=\":443\"",
        "cache-control": "no-cache",
        "strict-transport-security": "max-age=31536000",
      },
      hasSecurityTxt: false,
      logs: [],
    };

    // Plan 1 (Starter) verification
    saveLiveScanResult("asmt-test-p1", { ...baseProbe, planTier: 1, findings: sampleFindings });
    const p1Report = {
      id: "rep-p1",
      assessmentId: "asmt-test-p1",
      targetHost: "https://youtube.com",
      templateType: "TECHNICAL_FINDINGS" as const,
      format: "PDF" as const,
      title: "youtube - Security Assessment",
      status: "READY" as const,
      createdAt: new Date().toISOString(),
      sha256Digest: "sha256:0dd6e34da00f485487b89c4b4e48",
      sizeBytes: 154000,
      downloadUrl: "",
      redacted: true,
    };
    const docP1 = buildStructuredReport(p1Report);
    expect(docP1.planLabel).toBe("Plan 1 (Starter)");
    expect(docP1.postureScore).toBe(99);
    expect(docP1.postureGrade).toBe("A+");
    expect(docP1.riskScore).toBe("2.0");
    expect(docP1.findings.length).toBe(1);
    expect(docP1.tierGroups.length).toBe(1);
    expect(docP1.tables[0].rows[1][1]).toBe("Locked"); // Plan 2 locked
    expect(docP1.tables[0].rows[2][1]).toBe("Locked"); // Plan 3 locked
    expect(docP1.complianceRows.length).toBe(2);

    const pdfP1 = buildSecurityReportPdfBlob(p1Report);
    expect(pdfP1.size).toBeGreaterThan(1000);

    // Plan 2 (Pro SecOps) verification
    saveLiveScanResult("asmt-test-p2", { ...baseProbe, planTier: 2, findings: sampleFindings });
    const p2Report = { ...p1Report, id: "rep-p2", assessmentId: "asmt-test-p2" };
    const docP2 = buildStructuredReport(p2Report);
    expect(docP2.planLabel).toBe("Plan 2 (Pro SecOps)");
    expect(docP2.postureScore).toBe(89);
    expect(docP2.postureGrade).toBe("B+");
    expect(docP2.riskScore).toBe("4.9");
    expect(docP2.findings.length).toBe(3);
    expect(docP2.tierGroups.length).toBe(2);
    expect(docP2.tables[0].rows[1][1]).toBe("2"); // Plan 2 unlocked: 2 findings
    expect(docP2.tables[0].rows[2][1]).toBe("Locked"); // Plan 3 locked
    expect(docP2.complianceRows.length).toBe(4);

    // Plan 3 (Enterprise Perimeter) verification
    saveLiveScanResult("asmt-test-p3", { ...baseProbe, planTier: 3, findings: sampleFindings });
    const p3Report = { ...p1Report, id: "rep-p3", assessmentId: "asmt-test-p3" };
    const docP3 = buildStructuredReport(p3Report);
    expect(docP3.planLabel).toBe("Plan 3 (Enterprise Perimeter)");
    expect(docP3.postureScore).toBe(78);
    expect(docP3.postureGrade).toBe("B");
    expect(docP3.riskScore).toBe("4.9");
    expect(docP3.findings.length).toBe(8);
    expect(docP3.tierGroups.length).toBe(3);
    expect(docP3.tables[0].rows[1][1]).toBe("2");
    expect(docP3.tables[0].rows[2][1]).toBe("5");
    expect(docP3.complianceRows.length).toBe(6);
  });
});
