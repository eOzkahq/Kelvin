import { describe, it, expect, beforeEach, vi } from "vitest";
import { fetchAssessmentDetail, cancelAssessment } from "./assessmentApi";

describe("FE-07: Assessment Execution Monitoring Suite", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("retrieves live assessment details with multi-stage progression", async () => {
    const detail = await fetchAssessmentDetail("asmt-test-01");
    expect(detail.id).toBe("asmt-test-01");
    expect(detail.currentStage).toBeDefined();
    expect(["QUEUED", "PREFLIGHT", "SCANNING", "NORMALIZING", "COMPLETED", "CANCELLED", "FAILED"]).toContain(
      detail.currentStage
    );

    // Verify per-scanner worker progress
    expect(Array.isArray(detail.scanners)).toBe(true);
    expect(detail.scanners.length).toBeGreaterThan(0);
    const nuclei = detail.scanners.find((s) => s.scanner === "Nuclei");
    expect(nuclei).toBeDefined();

    // Verify streamed logs
    expect(Array.isArray(detail.logs)).toBe(true);
    expect(detail.logs.length).toBeGreaterThan(0);
    expect(detail.logs[0].message).toBeDefined();
  });

  it("sends cancellation signal to abort worker processes", async () => {
    const res = await cancelAssessment("asmt-test-01");
    expect(res.success).toBe(true);
  });
});
