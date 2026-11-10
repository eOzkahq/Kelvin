/**
 * Authoritative Remediation Types (FE-25 / ADR-FE-01 / ADR-FE-05)
 * Reconciled against Go backend remediation models and state machines.
 */

import type { FindingSeverity } from "../findings/types";

export type RemediationStatus =
  | "OPEN"
  | "PLANNED"
  | "IN_PROGRESS"
  | "BLOCKED"
  | "READY_FOR_VERIFICATION"
  | "VERIFICATION_PENDING"
  | "COMPLETED"
  | "RESOLVED"
  | "REOPENED"
  | "ACCEPTED_RISK"
  | "BACKLOG"
  | "VERIFYING";

export type VerificationStatus =
  | "NONE"
  | "UNVERIFIED"
  | "PENDING"
  | "VERIFICATION_PENDING"
  | "IN_PROGRESS"
  | "VERIFYING"
  | "VERIFIED"
  | "VERIFIED_RESOLVED"
  | "VERIFICATION_FAILED_STILL_PRESENT"
  | "FAILED"
  | "INCONCLUSIVE_INSUFFICIENT_COVERAGE";

export interface RemediationNote {
  id: string;
  author: string;
  content: string;
  createdAt: string;
}

export interface RemediationTask {
  id: string;
  findingId: string;
  findingTitle: string;
  title: string;
  description?: string;
  recommendedAction?: string;
  remediationGuidance?: string;
  status: RemediationStatus;
  severity: FindingSeverity;
  target: string;
  affectedEndpoint: string;
  assignee?: string;
  assignedUserId?: string;
  team?: string;
  dueDate?: string;
  targetCompletionDate?: string;
  verificationStatus: VerificationStatus;
  verificationAssessmentId?: string;
  slaHoursRemaining: number;
  isOverdue: boolean;
  prUrl?: string;
  commitSha?: string;
  notes: RemediationNote[];
  createdAt: string;
  updatedAt?: string;
}

export interface RemediationFilterParams {
  status?: RemediationStatus | RemediationStatus[];
  severity?: FindingSeverity | FindingSeverity[] | string;
  slaStatus?: "OVERDUE" | "HEALTHY" | "BREACH_RISK" | "ALL";
  priority?: string[];
  assignee?: string;
  target?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export interface VerificationTriggerResponse {
  verificationJobId: string;
  status: VerificationStatus;
}
