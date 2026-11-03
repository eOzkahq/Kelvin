export type AuditCategory =
  | "AUTHENTICATION"
  | "ASSESSMENT"
  | "FINDINGS"
  | "TARGETS"
  | "POLICY"
  | "ADMINISTRATION";

export type AuditOutcome = "SUCCESS" | "FAILURE";

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  category: AuditCategory;
  resourceType: string;
  resourceId: string;
  ipAddress: string;
  userAgent: string;
  correlationId: string;
  outcome: AuditOutcome;
  details: Record<string, any>;
  sha256Hash: string;
  prevRecordHash: string;
  chainVerified: boolean;
}

export interface AuditFilterParams {
  search?: string;
  category?: AuditCategory | "";
  outcome?: AuditOutcome | "";
  actor?: string;
  startDate?: string;
  endDate?: string;
  limit?: number;
  offset?: number;
}
