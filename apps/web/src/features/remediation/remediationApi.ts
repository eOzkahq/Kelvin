import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoRemediationProvider, INITIAL_TASKS } from "./demoProvider";
import type {
  RemediationFilterParams,
  RemediationNote,
  RemediationStatus,
  RemediationTask,
  VerificationStatus,
} from "./types";

export type {
  RemediationFilterParams,
  RemediationNote,
  RemediationStatus,
  RemediationTask,
  VerificationStatus,
};

export { INITIAL_TASKS };

export function calculateSlaStatus(
  dueDateStr: string,
  now: Date = new Date()
): { slaHoursRemaining: number; isOverdue: boolean } {
  const due = new Date(dueDateStr).getTime();
  const diffHours = Math.round((due - now.getTime()) / (1000 * 60 * 60));
  return {
    slaHoursRemaining: diffHours,
    isOverdue: diffHours < 0,
  };
}

export async function fetchRemediationTasks(
  filters?: RemediationFilterParams
): Promise<RemediationTask[]> {
  if (isDemoMode()) {
    return demoRemediationProvider.fetchRemediationTasks(filters);
  }

  const q = new URLSearchParams();
  if (filters?.status) {
    q.set("status", Array.isArray(filters.status) ? filters.status.join(",") : filters.status);
  }
  if (filters?.assignee) q.set("assignee", filters.assignee);
  if (filters?.target) q.set("target", filters.target);
  if (filters?.search) q.set("q", filters.search);
  const queryStr = q.toString() ? `?${q.toString()}` : "";
  return request<RemediationTask[]>(`/remediation/tasks${queryStr}`);
}

export async function updateTaskStatus(
  taskId: string,
  newStatus: RemediationStatus,
  note?: string
): Promise<RemediationTask> {
  if (isDemoMode()) {
    return demoRemediationProvider.updateTaskStatus(taskId, newStatus, note);
  }

  return request<RemediationTask>(`/remediation/tasks/${taskId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status: newStatus, note }),
  });
}

export async function triggerVerificationScan(
  taskId: string
): Promise<{ verificationJobId: string; status: VerificationStatus }> {
  if (isDemoMode()) {
    return demoRemediationProvider.triggerVerificationScan(taskId);
  }

  return request<{ verificationJobId: string; status: VerificationStatus }>(
    `/remediation/tasks/${taskId}/verify`,
    { method: "POST" }
  );
}

export async function addRemediationNote(
  taskId: string,
  author: string,
  content: string
): Promise<RemediationNote> {
  if (isDemoMode()) {
    return demoRemediationProvider.addRemediationNote(taskId, author, content);
  }

  return request<RemediationNote>(`/remediation/tasks/${taskId}/notes`, {
    method: "POST",
    body: JSON.stringify({ author, content }),
  });
}

export function resetMockRemediation(): void {
  demoRemediationProvider.resetMockRemediation();
}
