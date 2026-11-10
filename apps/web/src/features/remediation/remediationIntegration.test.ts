import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  fetchRemediationTasks,
  updateTaskStatus,
  triggerVerificationScan,
  addRemediationNote,
  calculateSlaStatus,
  resetMockRemediation,
} from "./remediationApi";
import type { RemediationTask } from "./types";

describe("FE-28: Remediation Workflow Integration Suite", () => {
  beforeEach(() => {
    resetMockRemediation();
    vi.restoreAllMocks();
  });

  it("calculates SLA status and overdue flags accurately", () => {
    const fixedNow = new Date("2026-11-10T12:00:00Z");

    // Past due date
    const pastSla = calculateSlaStatus("2026-11-10T06:00:00Z", fixedNow);
    expect(pastSla.isOverdue).toBe(true);
    expect(pastSla.slaHoursRemaining).toBe(-6);

    // Future due date
    const futureSla = calculateSlaStatus("2026-11-12T12:00:00Z", fixedNow);
    expect(futureSla.isOverdue).toBe(false);
    expect(futureSla.slaHoursRemaining).toBe(48);
  });

  it("retrieves remediation tasks conforming to authoritative RemediationTask schema with filtering", async () => {
    const tasks: RemediationTask[] = await fetchRemediationTasks({
      status: "OPEN",
    });

    expect(Array.isArray(tasks)).toBe(true);
    expect(tasks.length).toBeGreaterThan(0);
    tasks.forEach((t) => {
      expect(t.status).toBe("OPEN");
      expect(t.id).toMatch(/^rem-/);
      expect(t.findingId).toMatch(/^fnd-/);
      expect(t.verificationStatus).toBeDefined();
    });
  });

  it("filters tasks by target host", async () => {
    const tasks = await fetchRemediationTasks({
      target: "portal.staging",
    });

    expect(tasks.length).toBeGreaterThan(0);
    expect(tasks.every((t) => t.target.includes("portal.staging"))).toBe(true);
  });

  it("updates task status with audit note persistence", async () => {
    const updated = await updateTaskStatus(
      "rem-101",
      "READY_FOR_VERIFICATION",
      "Merged patch PR #432 into main staging container"
    );

    expect(updated.id).toBe("rem-101");
    expect(updated.status).toBe("READY_FOR_VERIFICATION");
    expect(updated.notes.some((n) => n.content.includes("Merged patch PR #432"))).toBe(true);
  });

  it("triggers follow-up verification scan returning job ID and transition", async () => {
    const res = await triggerVerificationScan("rem-101");

    expect(res).toBeDefined();
    expect(res.verificationJobId).toMatch(/^vjob-/);
    expect(res.status).toBe("VERIFYING");
  });

  it("adds collaboration note attributing authenticated author", async () => {
    const note = await addRemediationNote(
      "rem-102",
      "lead-secops@kelvin.io",
      "Validated SQL injection input sanitization in test database."
    );

    expect(note.id).toMatch(/^not-/);
    expect(note.author).toBe("lead-secops@kelvin.io");
    expect(note.content).toContain("Validated SQL injection");
  });
});
