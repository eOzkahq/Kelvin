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
});
