/**
 * Authoritative Assessment Types (FE-25 / ADR-FE-01 / ADR-FE-05)
 * Reconciled against Go backend DTOs and OpenAPI 3.1 contracts.
 */

export type AssessmentStatus =
  | "QUEUED"
  | "VALIDATING_SCOPE"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "TIMED_OUT"
  | "CANCELLED"
  | "PENDING"; // Backward-compatible alias for QUEUED

export type AssessmentStage =
  | "QUEUED"
  | "PREFLIGHT"
  | "DISCOVERY"
  | "SCANNING"
  | "VULN_SCAN"
  | "NORMALIZING"
  | "NORMALIZATION"
  | "REPORT_GEN"
  | "COMPLETED"
  | "CANCELLED"
  | "FAILED";

export interface ScannerExecution {
  id: string;
  scanner: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "TIMED_OUT";
  findingsCount: number;
  findingsDiscovered?: number;
  startTime?: string;
  endTime?: string;
  durationSeconds?: number;
  currentActivity?: string;
  error?: string;
}

export interface AssessmentLog {
  id: string;
  timestamp: string;
  level: "INFO" | "WARN" | "ERROR" | "DEBUG";
  message: string;
  stage?: string;
}

export interface AssessmentTarget {
  id?: string;
  host: string;
  name?: string;
  verified?: boolean;
}

export interface AssessmentRecord {
  id: string;
  name: string;
  targetId?: string;
  targetAddress: string;
  profileId: string;
  profileName: string;
  status: AssessmentStatus;
  criticalCount: number;
  highCount: number;
  totalFindings: number;
  createdAt: string;
  completedAt?: string;
  updatedAt?: string;
}

// Backward-compatibility alias
export type Assessment = AssessmentRecord;

export interface AssessmentDetail extends AssessmentRecord {
  currentStage: AssessmentStage;
  scanners: ScannerExecution[];
  logs: AssessmentLog[];
  errorMessage?: string;
  progressPercent?: number;
  targets?: AssessmentTarget[];
}

export interface CreateAssessmentPayload {
  name: string;
  targetId?: string;
  profileId: string;
  rateLimit?: number;
  timeoutMinutes?: number;
  authorizedScopeConfirmed: boolean;
  idempotencyKey: string;
  targets?: { host: string }[];
}

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  scanners: string[];
  riskLevel: "LOW" | "MEDIUM" | "HIGH";
}

export interface TargetOption {
  id: string;
  name: string;
  address: string;
  verified: boolean;
  environment: "PRODUCTION" | "STAGING" | "INTERNAL";
}

export interface AssessmentCancelResponse {
  success: boolean;
  message?: string;
}
