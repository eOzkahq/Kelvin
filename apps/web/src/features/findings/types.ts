/**
 * Authoritative Findings Types (FE-25 / ADR-FE-01 / ADR-FE-05)
 * Reconciled against Go backend persistent findings and OpenAPI 3.1 contracts.
 */

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingStatus =
  | "NEW"
  | "OPEN"
  | "CONFIRMED"
  | "IN_PROGRESS"
  | "RESOLVED"
  | "REOPENED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK"
  | "SUPPRESSED";

export interface FindingEvidence {
  id: string;
  findingId?: string;
  title?: string;
  name?: string;
  evidenceType?: string;
  contentType?: string;
  sizeBytes?: number;
  storagePath?: string;
  sha256?: string;
  rawPayload?: string;
  sanitizedPayload?: string;
  isSafe?: boolean;
  redactionCount?: number;
  url?: string;
  timestamp?: string;
  createdAt?: string;
}

export interface FindingObservation {
  id: string;
  findingId?: string;
  assessmentId?: string;
  assessmentTitle?: string;
  status?: string;
  scanner?: string;
  scannerId?: string;
  target?: string;
  timestamp?: string;
  observedAt?: string;
  evidenceRefs?: string[];
  evidenceCount?: number;
  rawMetadata?: Record<string, unknown>;
}

export interface FindingTimelineEntry {
  id: string;
  timestamp: string;
  actor: string;
  action?: string;
  fromStatus?: FindingStatus | string;
  toStatus: FindingStatus | string;
  justification?: string;
  note?: string;
}

export interface RiskContributingFactor {
  name?: string;
  factor?: string;
  weight: number;
  impact: string;
}

export interface RiskExplainability {
  formula: string;
  rationale?: string;
  contributingFactors: RiskContributingFactor[];
  baseCvss: number;
  contextualScore: number;
  signals?: string[];
}

export interface Finding {
  id: string;
  assessmentId?: string;
  fingerprint: string;
  title: string;
  severity: FindingSeverity;
  status: FindingStatus;
  target: string;
  affectedEndpoint: string;
  scanner: string;
  cvssScore?: number;
  riskScore: number;
  cweId?: string;
  cveIds?: string[];
  firstSeenAt: string;
  lastSeenAt: string;
  occurrenceCount?: number;
  assignee?: string;
  dueDate?: string;
  description?: string;
  remediation?: string;
  remediationGuidance?: string;
  remediationSlaDays?: number;
  requiredTier?: 1 | 2 | 3;
}

// Backward-compatible alias
export type FindingSummary = Finding;

export interface FindingDetail extends Finding {
  riskExplainability: RiskExplainability;
  evidence: FindingEvidence[];
  observations: FindingObservation[];
  auditTrail: FindingTimelineEntry[];
}

export interface FindingsFilterParams {
  search?: string;
  severity?: FindingSeverity | FindingSeverity[] | "";
  status?: FindingStatus | FindingStatus[] | "";
  scanner?: string;
  target?: string;
  assessmentId?: string;
  maxTier?: 1 | 2 | 3;
  page?: number;
  limit?: number;
  sort?: string;
  sortBy?: string;
  order?: "asc" | "desc";
  sortOrder?: "asc" | "desc";
}

export interface FindingsListResponse {
  items: Finding[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  lockedTierCounts?: {
    pro: number;
    enterprise: number;
  };
}

export interface BatchUpdatePayload {
  findingIds: string[];
  action?: "STATUS_TRANSITION" | "ASSIGN" | "SUPPRESS" | "MARK_FALSE_POSITIVE";
  status?: FindingStatus;
  assignee?: string;
  reason?: string;
  justification?: string;
}

export interface BatchUpdateResponse {
  updatedCount: number;
  success?: boolean;
  message?: string;
  errors?: { id: string; error: string }[];
}

export interface FindingTransitionPayload {
  targetStatus: FindingStatus;
  reason?: string;
  justification?: string;
  assignee?: string;
  dueDate?: string;
}
