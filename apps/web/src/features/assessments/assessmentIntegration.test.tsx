import { describe, it, expect, vi } from "vitest";
import { fetchAssessmentDetail, cancelAssessment } from "./assessmentApi";
import type { AssessmentDetail, AssessmentStatus } from "./types";

describe("FE-26: Assessment Integration Lifecycle Suite", () => {
  it("fetches assessment detail conforming to authoritative AssessmentDetail type", async () => {
    const detail: AssessmentDetail = await fetchAssessmentDetail("asmt-test-01");
    expect(detail).toBeDefined();
    expect(detail.id).toBe("asmt-test-01");
    expect(detail.status).toBeDefined();
    expect(detail.currentStage).toBeDefined();
    expect(Array.isArray(detail.scanners)).toBe(true);
    expect(Array.isArray(detail.logs)).toBe(true);
  });

  it("identifies terminal assessment states to halt polling", () => {
    const terminalStatuses: AssessmentStatus[] = ["COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"];
    const activeStatuses: AssessmentStatus[] = ["PENDING", "RUNNING"];

    const isTerminal = (status: AssessmentStatus) =>
      status === "COMPLETED" ||
      status === "FAILED" ||
      status === "CANCELLED" ||
      status === "TIMED_OUT";

    terminalStatuses.forEach((status) => {
      expect(isTerminal(status)).toBe(true);
    });

    activeStatuses.forEach((status) => {
      expect(isTerminal(status)).toBe(false);
    });
  });

  it("handles cancelAssessment mutation response correctly", async () => {
    const res = await cancelAssessment("asmt-test-01");
    expect(res).toBeDefined();
    expect(res.success).toBe(true);
  });

  it("propagates API rejection when backend fails cancellation", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      statusText: "Conflict",
      json: async () => ({ message: "Cannot cancel completed assessment" }),
    });
    vi.stubGlobal("fetch", mockFetch);

    try {
      await cancelAssessment("asmt-completed-01");
      expect.fail("Should have thrown error");
    } catch (err: unknown) {
      expect((err as Error).message).toContain("Failed to cancel assessment");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
