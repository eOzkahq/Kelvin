import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { isDemoMode, setDemoModeOverride } from "../config/env";
import { fetchAssessments } from "./assessments/assessmentApi";
import { fetchFindings } from "./findings/findingsApi";
import { fetchRemediationTasks } from "./remediation/remediationApi";

describe("FE-29: Demo Mode & Data Isolation Suite (ADR-FE-03 / ADR-FE-04)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    setDemoModeOverride(null);
    vi.unstubAllGlobals();
  });

  it("reports demo mode state correctly via isDemoMode()", () => {
    setDemoModeOverride(true);
    expect(isDemoMode()).toBe(true);

    setDemoModeOverride(false);
    expect(isDemoMode()).toBe(false);
  });

  it("returns in-memory demo fixtures when demo mode is active", async () => {
    setDemoModeOverride(true);

    const assessments = await fetchAssessments();
    expect(Array.isArray(assessments)).toBe(true);
    expect(assessments.length).toBeGreaterThan(0);
    expect(assessments.some((a) => a.id === "asmt-2026-001")).toBe(true);

    const findings = await fetchFindings();
    expect(Array.isArray(findings.items)).toBe(true);
    expect(findings.items.some((f) => f.id === "fnd-001")).toBe(true);

    const tasks = await fetchRemediationTasks();
    expect(Array.isArray(tasks)).toBe(true);
    expect(tasks.some((t) => t.id === "rem-101")).toBe(true);
  });

  it("NEVER falls back to demo data when production mode encounters 500 API errors", async () => {
    setDemoModeOverride(false);

    // Mock fetch to simulate backend 500 Internal Server Error
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({
        type: "https://kelvin.security/errors/internal-server-error",
        title: "Internal Server Error",
        status: 500,
        detail: "Database replica connection timed out",
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    // 1. Assessments API must throw ApiError and NOT return mockAssessments
    await expect(fetchAssessments()).rejects.toThrow();

    // 2. Findings API must throw ApiError and NOT return mockFindings
    await expect(fetchFindings()).rejects.toThrow();

    // 3. Remediation API must throw ApiError and NOT return mockTasks
    await expect(fetchRemediationTasks()).rejects.toThrow();
  });

  it("NEVER falls back to demo data when production mode encounters network connection errors", async () => {
    setDemoModeOverride(false);

    // Mock fetch to simulate network partition / offline
    const networkFailure = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", networkFailure);

    await expect(fetchAssessments()).rejects.toThrow("Failed to fetch");
    await expect(fetchFindings()).rejects.toThrow("Failed to fetch");
    await expect(fetchRemediationTasks()).rejects.toThrow("Failed to fetch");
  });
});
