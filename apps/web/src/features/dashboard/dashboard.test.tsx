import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchDashboardData } from "./dashboardApi";

describe("FE-05: Security Overview Dashboard Suite", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches dashboard data including KPI metrics, findings, and active jobs", async () => {
    const data = await fetchDashboardData("30d");

    expect(data.metrics).toBeDefined();
    expect(data.metrics.totalAssessments).toBeGreaterThan(0);
    expect(data.metrics.totalFindings).toBeGreaterThan(0);

    // Verify canonical severity distribution counts
    const { severityDistribution } = data.metrics;
    expect(severityDistribution.critical).toBeGreaterThanOrEqual(0);
    expect(severityDistribution.high).toBeGreaterThanOrEqual(0);
    expect(severityDistribution.medium).toBeGreaterThanOrEqual(0);
    expect(severityDistribution.low).toBeGreaterThanOrEqual(0);
    expect(severityDistribution.info).toBeGreaterThanOrEqual(0);

    // Verify scanner readiness status
    expect(data.metrics.scannerReadiness.nmap).toBe(true);
    expect(data.metrics.scannerReadiness.nuclei).toBe(true);
    expect(data.metrics.scannerReadiness.trivy).toBe(true);
    expect(data.metrics.scannerReadiness.zap).toBe(true);

    // Verify recent findings list
    expect(Array.isArray(data.recentFindings)).toBe(true);
    expect(data.recentFindings.length).toBeGreaterThan(0);
    expect(data.recentFindings[0].severity).toBe("CRITICAL");

    // Verify active jobs list
    expect(Array.isArray(data.activeJobs)).toBe(true);
    expect(data.activeJobs[0].status).toBe("RUNNING");
  });

  it("calculates severity percentages accurately", async () => {
    const data = await fetchDashboardData("7d");
    const { severityDistribution, totalFindings } = data.metrics;

    const sum =
      severityDistribution.critical +
      severityDistribution.high +
      severityDistribution.medium +
      severityDistribution.low +
      severityDistribution.info;

    expect(sum).toBe(totalFindings);
  });
});
