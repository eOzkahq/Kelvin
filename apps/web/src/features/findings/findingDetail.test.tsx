import { describe, it, expect, beforeEach } from "vitest";
import {
  sanitizeEvidence,
  escapeHtml,
  stripScriptTags,
  redactSensitivePatterns,
} from "./evidenceSanitizer";
import {
  getFindingDetail,
  transitionFindingStatus,
  resetMockFindings,
} from "./findingsApi";

describe("Evidence Sanitizer & Secret Redaction Engine (FE-09 / ADR-0005)", () => {
  it("escapes dangerous HTML characters to prevent XSS", () => {
    const raw = `<img src=x onerror="alert('XSS')"> & 'quote'`;
    const escaped = escapeHtml(raw);
    expect(escaped).not.toContain("<img");
    expect(escaped).toContain("&lt;img");
    expect(escaped).toContain("&amp;");
  });

  it("strips script tags and inline event handlers from evidence payloads", () => {
    const malicious = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(document.cookie)</script><div onmouseover="stealTokens()">Reflected</div>`;
    const stripped = stripScriptTags(malicious);
    expect(stripped).not.toContain("<script>");
    expect(stripped).toContain("[REMOVED_DANGEROUS_SCRIPT_TAG]");
    expect(stripped).toContain("[REMOVED_INLINE_EVENT_HANDLER]");
  });

  it("redacts Bearer JWT tokens from HTTP Authorization headers", () => {
    const authHeader = `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doz_signature`;
    const { text, count } = redactSensitivePatterns(authHeader);
    expect(count).toBeGreaterThan(0);
    expect(text).toContain("Authorization: Bearer [REDACTED_JWT_TOKEN]");
    expect(text).not.toContain("eyJhbGci");
  });

  it("redacts session cookies and sensitive passwords", () => {
    const payload = `Cookie: sessionid=sess_abcdef123456789; other=1\r\n{"password":"MySecretPassword123"}`;
    const { text, count } = redactSensitivePatterns(payload);
    expect(count).toBeGreaterThanOrEqual(2);
    expect(text).toContain("[REDACTED_SESSION]");
    expect(text).toContain("[REDACTED_PASSWORD]");
    expect(text).not.toContain("MySecretPassword123");
  });

  it("processes complex scanner proof-of-concept through sanitizeEvidence", () => {
    const rawPoc = `POST /api/v1/login HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature\r\nCookie: token=secret-session-token-99\r\n\r\n<script>alert(1)</script>{"password":"secret"}`;
    const result = sanitizeEvidence(rawPoc);
    expect(result.isSafeForDisplay).toBe(true);
    expect(result.hasRedactions).toBe(true);
    expect(result.redactionCount).toBeGreaterThan(0);
    expect(result.sanitized).toContain("[REMOVED_DANGEROUS_SCRIPT_TAG]");
    expect(result.sanitized).toContain("[REDACTED_JWT_TOKEN]");
    expect(result.sanitized).toContain("[REDACTED_SESSION]");
    expect(result.sanitized).toContain("[REDACTED_PASSWORD]");
  });
});

describe("Finding Detail & Triage API (FE-09)", () => {
  beforeEach(() => {
    resetMockFindings();
  });

  it("fetches finding detail including risk explainability and evidence items", async () => {
    const detail = await getFindingDetail("fnd-001");
    expect(detail).toBeDefined();
    expect(detail.id).toBe("fnd-001");
    expect(detail.riskExplainability).toBeDefined();
    expect(detail.riskExplainability.formula).toContain("min(10.0");
    expect(detail.riskExplainability.contributingFactors.length).toBeGreaterThan(0);

    // Evidence
    expect(detail.evidence.length).toBeGreaterThan(0);
    expect(detail.evidence[0].sha256).toBeDefined();
    expect(detail.evidence[0].sanitizedPayload).toBeDefined();

    // Observations
    expect(detail.observations.length).toBeGreaterThan(0);
    expect(detail.observations[0].scanner).toBeDefined();

    // Audit Trail
    expect(detail.auditTrail.length).toBeGreaterThan(0);
  });

  it("transitions finding state with audit trail logging", async () => {
    const updated = await transitionFindingStatus(
      "fnd-001",
      "RESOLVED",
      "Applied patch log4j 2.17.1 to production containers",
      "lead-analyst@kelvin.io"
    );

    expect(updated.status).toBe("RESOLVED");
    expect(updated.assignee).toBe("lead-analyst@kelvin.io");
    expect(updated.auditTrail.length).toBeGreaterThan(0);
    expect(updated.auditTrail[0].toStatus).toBe("RESOLVED");
    expect(updated.auditTrail[0].justification).toContain("Applied patch log4j");
  });
});
