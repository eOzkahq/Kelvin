import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchRemediationTasks,
  updateTaskStatus,
  triggerVerificationScan,
  addRemediationNote,
  resetMockRemediation,
} from "./remediationApi";

describe("Remediation Management Workspace (FE-10)", () => {
  beforeEach(() => {
    resetMockRemediation();
  });

  it("fetches active remediation task list with SLA countdown metadata", async () => {
    const tasks = await fetchRemediationTasks();
    expect(tasks).toBeDefined();
    expect(tasks.length).toBeGreaterThan(0);

    const first = tasks[0];
    expect(first.findingTitle).toBeDefined();
    expect(first.severity).toBeDefined();
    expect(first.assignee).toBeDefined();
    expect(typeof first.slaHoursRemaining).toBe("number");
    expect(typeof first.isOverdue).toBe("boolean");
  });

  it("filters remediation tasks by SLA status accurately", async () => {
    // Overdue tasks
    const overdue = await fetchRemediationTasks({ slaStatus: "OVERDUE" });
    expect(overdue.length).toBeGreaterThan(0);
    overdue.forEach((t) => {
      expect(t.isOverdue).toBe(true);
    });

    // Healthy tasks
    const healthy = await fetchRemediationTasks({ slaStatus: "HEALTHY" });
    expect(healthy.length).toBeGreaterThan(0);
    healthy.forEach((t) => {
      expect(t.isOverdue).toBe(false);
      expect(t.slaHoursRemaining).toBeGreaterThan(48);
    });
  });

  it("filters tasks by lifecycle status", async () => {
    const inProgress = await fetchRemediationTasks({ status: "IN_PROGRESS" });
    expect(inProgress.length).toBeGreaterThan(0);
    inProgress.forEach((t) => {
      expect(t.status).toBe("IN_PROGRESS");
    });
  });

  it("updates task lifecycle state with progress note", async () => {
    const updated = await updateTaskStatus(
      "rem-101",
      "RESOLVED",
      "Fix deployed to production cluster and verified by engineer."
    );

    expect(updated.status).toBe("RESOLVED");
    expect(updated.notes.some((n) => n.content.includes("Fix deployed"))).toBe(true);
  });

  it("triggers automated verification scan and updates task state", async () => {
    const res = await triggerVerificationScan("rem-102");
    expect(res.verificationJobId).toBeDefined();
    expect(res.status).toBe("VERIFYING");

    // Check updated task status
    const tasks = await fetchRemediationTasks();
    const task = tasks.find((t) => t.id === "rem-102");
    expect(task?.status).toBe("VERIFICATION_PENDING");
    expect(task?.verificationStatus).toBe("VERIFYING");
  });

  it("adds collaboration notes to remediation task thread", async () => {
    const note = await addRemediationNote(
      "rem-101",
      "sec-team@kelvin.io",
      "Automated unit regression test passed."
    );

    expect(note.id).toBeDefined();
    expect(note.author).toBe("sec-team@kelvin.io");
    expect(note.content).toContain("Automated unit regression");
  });
});
