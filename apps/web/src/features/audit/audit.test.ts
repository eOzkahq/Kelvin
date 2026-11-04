import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchAuditLogs,
  exportAuditLogs,
  resetMockAudit,
} from "./auditApi";

describe("Audit Logs & Activity Interface (FE-16)", () => {
  beforeEach(() => {
    resetMockAudit();
  });

  it("retrieves immutable audit trail with cryptographic hash-chain metadata", async () => {
    const logs = await fetchAuditLogs();
    expect(logs).toBeDefined();
    expect(logs.length).toBeGreaterThan(0);

    const first = logs[0];
    expect(first.id).toBeDefined();
    expect(first.timestamp).toBeDefined();
    expect(first.actor).toBeDefined();
    expect(first.action).toBeDefined();
    expect(first.sha256Hash).toBeDefined();
    expect(first.prevRecordHash).toBeDefined();
    expect(first.chainVerified).toBe(true);
  });

  it("filters audit events by category", async () => {
    const authLogs = await fetchAuditLogs({ category: "AUTHENTICATION" });
    expect(authLogs.length).toBeGreaterThan(0);
    authLogs.forEach((l) => {
      expect(l.category).toBe("AUTHENTICATION");
    });

    const findingsLogs = await fetchAuditLogs({ category: "FINDINGS" });
    expect(findingsLogs.length).toBeGreaterThan(0);
    findingsLogs.forEach((l) => {
      expect(l.category).toBe("FINDINGS");
    });
  });

  it("filters audit events by outcome", async () => {
    const failures = await fetchAuditLogs({ outcome: "FAILURE" });
    expect(failures.length).toBeGreaterThan(0);
    failures.forEach((l) => {
      expect(l.outcome).toBe("FAILURE");
    });
  });

  it("exports audit logs as standard CSV data", async () => {
    const csv = await exportAuditLogs("csv");
    const lines = csv.split("\n");
    expect(lines.length).toBeGreaterThan(1);
    expect(lines[0]).toContain("Timestamp UTC");
    expect(lines[0]).toContain("SHA-256 Hash");
    expect(lines[0]).toContain("Correlation ID");
  });

  it("exports audit logs as NDJSON formatted records", async () => {
    const ndjson = await exportAuditLogs("ndjson");
    const lines = ndjson.split("\n").filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);

    const parsedFirst = JSON.parse(lines[0]);
    expect(parsedFirst.id).toBeDefined();
    expect(parsedFirst.chainVerified).toBe(true);
  });
});
