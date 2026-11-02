/**
 * Kelvin Enterprise Permission Catalog (P4-09)
 * Maps 1:1 to apps/api/internal/iam/permissions.go
 */

export type ScopeLevel = "ORGANIZATION" | "WORKSPACE";

export interface PermissionMetadata {
  code: string;
  resource: string;
  action: string;
  scope: ScopeLevel;
  description: string;
  is_privileged: boolean;
}

export const PERMISSIONS = {
  // Organization
  ORG_READ: "org:read",
  ORG_ADMIN: "org:admin",
  ORG_SETTINGS_WRITE: "org:settings:write",
  ORG_MEMBERS_MANAGE: "org:members:manage",
  ORG_BILLING_MANAGE: "org:billing:manage",
  ORG_SSO_MANAGE: "org:sso:manage",

  // Workspace
  WORKSPACE_READ: "workspace:read",
  WORKSPACE_CREATE: "workspace:create",
  WORKSPACE_ADMIN: "workspace:admin",
  WORKSPACE_SETTINGS_WRITE: "workspace:settings:write",

  // Team
  TEAM_READ: "team:read",
  TEAM_CREATE: "team:create",
  TEAM_ADMIN: "team:admin",
  TEAM_MEMBERS_MANAGE: "team:members:manage",

  // Target
  TARGET_READ: "target:read",
  TARGET_CREATE: "target:create",
  TARGET_UPDATE: "target:update",
  TARGET_DELETE: "target:delete",

  // Assessment
  ASSESSMENT_READ: "assessment:read",
  ASSESSMENT_CREATE: "assessment:create",
  ASSESSMENT_EXECUTE: "assessment:execute",
  ASSESSMENT_CANCEL: "assessment:cancel",
  ASSESSMENT_DELETE: "assessment:delete",

  // Finding
  FINDING_READ: "finding:read",
  FINDING_TRIAGE: "finding:triage",
  FINDING_SUPPRESS: "finding:suppress",
  FINDING_EXPORT: "finding:export",

  // Evidence
  EVIDENCE_READ: "evidence:read",
  EVIDENCE_DOWNLOAD: "evidence:download",
  EVIDENCE_PURGE: "evidence:purge",
  EVIDENCE_HOLD_MANAGE: "evidence:hold:manage",

  // Remediation
  REMEDIATION_READ: "remediation:read",
  REMEDIATION_ASSIGN: "remediation:assign",
  REMEDIATION_UPDATE: "remediation:update",
  REMEDIATION_VERIFY: "remediation:verify",

  // Report
  REPORT_READ: "report:read",
  REPORT_GENERATE: "report:generate",
  REPORT_DOWNLOAD: "report:download",
  REPORT_EXPORT: "report:export",

  // Policy
  POLICY_READ: "policy:read",
  POLICY_ADMIN: "policy:admin",
  POLICY_SIMULATE: "policy:simulate",
  POLICY_EXCEPTION_APPROVE: "policy:exception:approve",

  // Integration & Webhook
  INTEGRATION_READ: "integration:read",
  INTEGRATION_CONFIGURE: "integration:configure",
  WEBHOOK_MANAGE: "webhook:manage",

  // Audit
  AUDIT_READ: "audit:read",
  AUDIT_EXPORT: "audit:export",
} as const;

export type PermissionCode = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];
