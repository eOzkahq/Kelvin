import type { FindingSeverity } from "../findings/types";

export type RemediationStatus =
  | "OPEN"
  | "IN_PROGRESS"
  | "BLOCKED"
  | "VERIFICATION_PENDING"
  | "RESOLVED"
  | "ACCEPTED_RISK";

export type VerificationStatus =
  | "UNVERIFIED"
  | "VERIFICATION_QUEUED"
  | "VERIFYING"
  | "VERIFIED_RESOLVED"
  | "VERIFICATION_FAILED";

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
  severity: FindingSeverity;
  target: string;
  affectedEndpoint: string;
  assignee: string;
  team: string;
  status: RemediationStatus;
  verificationStatus: VerificationStatus;
  dueDate: string;
  slaHoursRemaining: number;
  isOverdue: boolean;
  remediationGuidance: string;
  prUrl?: string;
  commitSha?: string;
  notes: RemediationNote[];
  updatedAt: string;
}

export interface RemediationFilterParams {
  search?: string;
  status?: RemediationStatus | "";
  severity?: FindingSeverity | "";
  assignee?: string;
  slaStatus?: "ALL" | "OVERDUE" | "BREACH_RISK" | "HEALTHY";
  target?: string;
}
