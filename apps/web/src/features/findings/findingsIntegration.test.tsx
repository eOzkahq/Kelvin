import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchFindings,
  getFindingDetail,
  transitionFindingStatus,
  batchUpdateFindings,
  exportFindings,
  exportFindingsBlob,
  resetMockFindings,
} from "./findingsApi";
import { sanitizeEvidence } from "./evidenceSanitizer";
import type { Finding, FindingDetail, FindingsListResponse } from "./types";

describe("FE-27: Findings Integration Suite", () => {
  beforeEach(() => {
    resetMockFindings();
  });

  it("fetches findings matching authoritative Finding contract with pagination and filtering", async () => {
    const res: FindingsListResponse = await fetchFindings({
      severity: "CRITICAL",
      page: 1,
      limit: 10,
    });

    expect(res).toBeDefined();
    expect(Array.isArray(res.items)).toBe(true);
    expect(res.items.length).toBeGreaterThan(0);
    expect(res.total).toBeGreaterThanOrEqual(res.items.length);
    res.items.forEach((item: Finding) => {
      expect(item.severity).toBe("CRITICAL");
      expect(item.id).toMatch(/^fnd-/);
      expect(item.fingerprint).toBeDefined();
    });
  });

  it("retrieves rich finding detail conforming to FindingDetail schema", async () => {
    const detail: FindingDetail = await getFindingDetail("fnd-001");
    expect(detail).toBeDefined();
    expect(detail.id).toBe("fnd-001");
    expect(detail.riskExplainability).toBeDefined();
    expect(detail.riskExplainability.baseCvss).toBeGreaterThan(0);
    expect(Array.isArray(detail.evidence)).toBe(true);
    expect(Array.isArray(detail.observations)).toBe(true);
    expect(Array.isArray(detail.auditTrail)).toBe(true);
  });

  it("transitions finding status and updates audit trail with justification", async () => {
    const detail = await transitionFindingStatus(
      "fnd-002",
      "RESOLVED",
      "Applied parameterized query patch across user search service",
      "security-engineer@kelvin.io"
    );

    expect(detail.status).toBe("RESOLVED");
    expect(detail.auditTrail[0].toStatus).toBe("RESOLVED");
    expect(detail.auditTrail[0].justification).toContain("parameterized query patch");
  });

  it("handles batch status updates and reports partial batch results when IDs are missing", async () => {
    const res = await batchUpdateFindings({
      findingIds: ["fnd-001", "fnd-nonexistent-999"],
      status: "IN_PROGRESS",
      assignee: "triage-bot@kelvin.io",
    });

    expect(res).toBeDefined();
    expect(res.updatedCount).toBe(1);
    expect(res.success).toBe(false);
    expect(res.errors).toBeDefined();
    expect(res.errors?.length).toBe(1);
    expect(res.errors?.[0].id).toBe("fnd-nonexistent-999");
  });

  it("exports findings into CSV and JSON formatted string payloads and blobs", async () => {
    const csv = await exportFindings("csv", { severity: "CRITICAL" });
    expect(csv).toContain("ID,Title,Severity,Status");
    expect(csv).toContain("fnd-001");

    const json = await exportFindings("json", { severity: "CRITICAL" });
    const parsed = JSON.parse(json);
    expect(Array.isArray(parsed)).toBe(true);

    const blob = await exportFindingsBlob("csv", { severity: "CRITICAL" });
    expect(blob).toBeDefined();
    expect(blob.type).toContain("text/csv");
  });

  it("sanitizes untrusted scanner evidence neutralizing XSS and redacting credentials", () => {
    const untrustedPayload =
      'HTTP/1.1 200 OK\r\nAuthorization: Bearer secret_access_token_12345.sig\r\nCookie: sessionid=admin_session_1234\r\n\r\n<script>alert("hacked")</script><img src=x onerror=alert(1)>';

    const result = sanitizeEvidence(untrustedPayload);
    expect(result.isSafeForDisplay).toBe(true);
    expect(result.sanitized).not.toContain("<script>");
    expect(result.sanitized).not.toContain("secret_access_token_12345");
    expect(result.sanitized).not.toContain("admin_session_1234");
    expect(result.sanitized).toContain("[REDACTED_JWT_TOKEN]");
    expect(result.sanitized).toContain("[REDACTED_SESSION]");
  });
});
