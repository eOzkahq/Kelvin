import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  fetchAssessments,
  fetchProfiles,
  fetchTargets,
  createAssessment,
} from "./assessmentApi";

describe("FE-06: Assessment Management & Creation Wizard Suite", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches assessment catalog records with status and finding counts", async () => {
    const list = await fetchAssessments();
    expect(Array.isArray(list)).toBe(true);
    expect(list.length).toBeGreaterThan(0);

    const first = list[0];
    expect(first.id).toMatch(/^asmt-/);
    expect(first.targetAddress).toBeDefined();
    expect(["PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]).toContain(first.status);
  });

  it("retrieves available scan profiles with scanner allocations", async () => {
    const profiles = await fetchProfiles();
    expect(profiles.length).toBeGreaterThan(0);

    const baseline = profiles.find((p) => p.id === "prof-web-baseline");
    expect(baseline).toBeDefined();
    expect(baseline?.scanners).toContain("ZAP");
  });

  it("retrieves verified enterprise targets", async () => {
    const targets = await fetchTargets();
    expect(targets.length).toBeGreaterThan(0);
    expect(targets.every((t) => t.verified)).toBe(true);
  });

  it("creates assessment job with idempotency key and authorization confirmation", async () => {
    const payload = {
      name: "Q4 Integration Test Scan",
      targetId: "tgt-001",
      profileId: "prof-web-baseline",
      rateLimit: 50,
      timeoutMinutes: 30,
      authorizedScopeConfirmed: true,
      idempotencyKey: "idem-test-12345",
    };

    const res = await createAssessment(payload);
    expect(res.id).toBeDefined();
    expect(res.id).toMatch(/^asmt-/);
  });
});
