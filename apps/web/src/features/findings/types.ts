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

export interface RiskExplainability {
  compositeScore: number;
  baseCvss: number;
  assetCriticality: number; // e.g. 1.2
  confidenceFactor: number; // e.g. 0.95
  exposureFactor: number; // e.g. 1.1
  formula: string;
  rationale: string;
  contributingFactors: {
    factor: string;
    weight: string;
    impact: string;
  }[];
}

export interface FindingEvidence {
  id: string;
  findingId: string;
  title: string;
  evidenceType: "HTTP_REQUEST" | "HTTP_RESPONSE" | "SCANNER_RAW" | "DOM_DUMP" | "CONFIG_SNIPPET";
  rawPayload: string;
  sanitizedPayload: string;
  isRedacted: boolean;
  sha256: string;
  timestamp: string;
}

export interface FindingObservationItem {
  id: string;
  assessmentId: string;
  assessmentTitle: string;
  scanner: string;
  observedAt: string;
  status: FindingStatus;
  evidenceCount: number;
}

export interface FindingAuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  fromStatus?: FindingStatus;
  toStatus?: FindingStatus;
  justification?: string;
}

export interface FindingDetail extends Finding {
  remediationSlaDays?: number;
  dueDate?: string;
  isSlaBreached?: boolean;
  riskExplainability: RiskExplainability;
  evidence: FindingEvidence[];
  observations: FindingObservationItem[];
  auditTrail: FindingAuditEntry[];
}

