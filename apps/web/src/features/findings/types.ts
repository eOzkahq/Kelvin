export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingStatus =
  | "OPEN"
  | "CONFIRMED"
  | "IN_PROGRESS"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK";

export interface FindingSummary {
  id: string;
  fingerprint: string;
  title: string;
  severity: FindingSeverity;
  status: FindingStatus;
  target: string;
  scanner: string;
  cvssScore?: number;
  riskScore: number;
  cweId?: string;
  cveIds?: string[];
  affectedEndpoint: string;
  firstSeenAt: string;
  lastSeenAt: string;
  assignee?: string;
  description?: string;
  remediation?: string;
}

export type Finding = FindingSummary;

export interface FindingsFilterParams {
  search?: string;
  severity?: FindingSeverity | "";
  status?: FindingStatus | "";
  target?: string;
  scanner?: string;
  sortBy?: "severity" | "riskScore" | "lastSeenAt" | "title";
  sortOrder?: "asc" | "desc";
  page?: number;
  limit?: number;
}

export interface FindingsListResponse {
  items: Finding[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface BatchUpdatePayload {
  findingIds: string[];
  status?: FindingStatus;
  assignee?: string;
  justification?: string;
}

export interface BatchUpdateResponse {
  updatedCount: number;
  success: boolean;
  message?: string;
}
