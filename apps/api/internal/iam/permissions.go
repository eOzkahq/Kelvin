package iam

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Permission represents a fine-grained enterprise action capability.
type Permission string

const (
	// Organization permissions
	PermissionOrgRead          Permission = "org:read"
	PermissionOrgAdmin         Permission = "org:admin"
	PermissionOrgSettingsWrite Permission = "org:settings:write"
	PermissionOrgMembersManage Permission = "org:members:manage"
	PermissionOrgBillingManage Permission = "org:billing:manage"
	PermissionOrgSSOManage     Permission = "org:sso:manage"

	// Workspace permissions
	PermissionWorkspaceRead          Permission = "workspace:read"
	PermissionWorkspaceCreate        Permission = "workspace:create"
	PermissionWorkspaceAdmin         Permission = "workspace:admin"
	PermissionWorkspaceSettingsWrite Permission = "workspace:settings:write"

	// Team permissions
	PermissionTeamRead          Permission = "team:read"
	PermissionTeamCreate        Permission = "team:create"
	PermissionTeamAdmin         Permission = "team:admin"
	PermissionTeamMembersManage Permission = "team:members:manage"

	// Target permissions
	PermissionTargetRead   Permission = "target:read"
	PermissionTargetCreate Permission = "target:create"
	PermissionTargetUpdate Permission = "target:update"
	PermissionTargetDelete Permission = "target:delete"

	// Assessment permissions
	PermissionAssessmentRead    Permission = "assessment:read"
	PermissionAssessmentCreate  Permission = "assessment:create"
	PermissionAssessmentExecute Permission = "assessment:execute"
	PermissionAssessmentCancel  Permission = "assessment:cancel"
	PermissionAssessmentDelete  Permission = "assessment:delete"

	// Finding permissions
	PermissionFindingRead     Permission = "finding:read"
	PermissionFindingTriage   Permission = "finding:triage"
	PermissionFindingSuppress Permission = "finding:suppress"
	PermissionFindingExport   Permission = "finding:export"

	// Evidence permissions
	PermissionEvidenceRead       Permission = "evidence:read"
	PermissionEvidenceDownload   Permission = "evidence:download"
	PermissionEvidencePurge      Permission = "evidence:purge"
	PermissionEvidenceHoldManage Permission = "evidence:hold:manage"

	// Remediation permissions
	PermissionRemediationRead   Permission = "remediation:read"
	PermissionRemediationAssign Permission = "remediation:assign"
	PermissionRemediationUpdate Permission = "remediation:update"
	PermissionRemediationVerify Permission = "remediation:verify"

	// Report permissions
	PermissionReportRead     Permission = "report:read"
	PermissionReportGenerate Permission = "report:generate"
	PermissionReportDownload Permission = "report:download"
	PermissionReportExport   Permission = "report:export"

	// Policy permissions
	PermissionPolicyRead             Permission = "policy:read"
	PermissionPolicyAdmin            Permission = "policy:admin"
	PermissionPolicySimulate         Permission = "policy:simulate"
	PermissionPolicyExceptionApprove Permission = "policy:exception:approve"

	// Integration & Webhook permissions
	PermissionIntegrationRead      Permission = "integration:read"
	PermissionIntegrationConfigure Permission = "integration:configure"
	PermissionWebhookManage        Permission = "webhook:manage"

	// Audit permissions
	PermissionAuditRead   Permission = "audit:read"
	PermissionAuditExport Permission = "audit:export"
)

// ScopeLevel identifies whether a permission operates at Organization or Workspace level.
type ScopeLevel string

const (
	ScopeOrganization ScopeLevel = "ORGANIZATION"
	ScopeWorkspace    ScopeLevel = "WORKSPACE"
)

// PermissionMetadata describes a registered permission and its security attributes.
type PermissionMetadata struct {
	Code         Permission `json:"code"`
	Resource     string     `json:"resource"`
	Action       string     `json:"action"`
	Scope        ScopeLevel `json:"scope"`
	Description  string     `json:"description"`
	IsPrivileged bool       `json:"is_privileged"`
}

var (
	ErrInvalidPermissionFormat = errors.New("permission does not conform to resource:action format")
	ErrUnregisteredPermission  = errors.New("unregistered permission code")
)

var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]+(:[a-z][a-z0-9_-]+)+$`)

// catalog holds the authoritative definitions for all Kelvin permissions.
var catalog = map[Permission]PermissionMetadata{
	// Org
	PermissionOrgRead:          {Code: PermissionOrgRead, Resource: "org", Action: "read", Scope: ScopeOrganization, Description: "View organization profile and metadata", IsPrivileged: false},
	PermissionOrgAdmin:         {Code: PermissionOrgAdmin, Resource: "org", Action: "admin", Scope: ScopeOrganization, Description: "Full administrative governance of organization", IsPrivileged: true},
	PermissionOrgSettingsWrite: {Code: PermissionOrgSettingsWrite, Resource: "org", Action: "settings:write", Scope: ScopeOrganization, Description: "Configure organization-level preferences and policies", IsPrivileged: true},
	PermissionOrgMembersManage: {Code: PermissionOrgMembersManage, Resource: "org", Action: "members:manage", Scope: ScopeOrganization, Description: "Invite, update roles, or remove organization members", IsPrivileged: true},
	PermissionOrgBillingManage: {Code: PermissionOrgBillingManage, Resource: "org", Action: "billing:manage", Scope: ScopeOrganization, Description: "Manage subscription plans and billing accounts", IsPrivileged: true},
	PermissionOrgSSOManage:     {Code: PermissionOrgSSOManage, Resource: "org", Action: "sso:manage", Scope: ScopeOrganization, Description: "Configure SAML/OIDC enterprise identity providers", IsPrivileged: true},

	// Workspace
	PermissionWorkspaceRead:          {Code: PermissionWorkspaceRead, Resource: "workspace", Action: "read", Scope: ScopeWorkspace, Description: "View workspace details and overview", IsPrivileged: false},
	PermissionWorkspaceCreate:        {Code: PermissionWorkspaceCreate, Resource: "workspace", Action: "create", Scope: ScopeOrganization, Description: "Provision new operational workspaces", IsPrivileged: true},
	PermissionWorkspaceAdmin:         {Code: PermissionWorkspaceAdmin, Resource: "workspace", Action: "admin", Scope: ScopeWorkspace, Description: "Administer workspace settings and team access", IsPrivileged: true},
	PermissionWorkspaceSettingsWrite: {Code: PermissionWorkspaceSettingsWrite, Resource: "workspace", Action: "settings:write", Scope: ScopeWorkspace, Description: "Modify workspace configuration overrides", IsPrivileged: false},

	// Team
	PermissionTeamRead:          {Code: PermissionTeamRead, Resource: "team", Action: "read", Scope: ScopeOrganization, Description: "View team profiles and member rosters", IsPrivileged: false},
	PermissionTeamCreate:        {Code: PermissionTeamCreate, Resource: "team", Action: "create", Scope: ScopeOrganization, Description: "Create new collaborative teams", IsPrivileged: false},
	PermissionTeamAdmin:         {Code: PermissionTeamAdmin, Resource: "team", Action: "admin", Scope: ScopeOrganization, Description: "Administer team profile and archival", IsPrivileged: true},
	PermissionTeamMembersManage: {Code: PermissionTeamMembersManage, Resource: "team", Action: "members:manage", Scope: ScopeOrganization, Description: "Add or remove members from team", IsPrivileged: false},

	// Target
	PermissionTargetRead:   {Code: PermissionTargetRead, Resource: "target", Action: "read", Scope: ScopeWorkspace, Description: "View target assets and scope limits", IsPrivileged: false},
	PermissionTargetCreate: {Code: PermissionTargetCreate, Resource: "target", Action: "create", Scope: ScopeWorkspace, Description: "Add target assets to workspace scope", IsPrivileged: false},
	PermissionTargetUpdate: {Code: PermissionTargetUpdate, Resource: "target", Action: "update", Scope: ScopeWorkspace, Description: "Update target asset configuration and tags", IsPrivileged: false},
	PermissionTargetDelete: {Code: PermissionTargetDelete, Resource: "target", Action: "delete", Scope: ScopeWorkspace, Description: "Remove target assets from workspace", IsPrivileged: true},

	// Assessment
	PermissionAssessmentRead:    {Code: PermissionAssessmentRead, Resource: "assessment", Action: "read", Scope: ScopeWorkspace, Description: "View assessment runs, logs, and status", IsPrivileged: false},
	PermissionAssessmentCreate:  {Code: PermissionAssessmentCreate, Resource: "assessment", Action: "create", Scope: ScopeWorkspace, Description: "Define and schedule new assessments", IsPrivileged: false},
	PermissionAssessmentExecute: {Code: PermissionAssessmentExecute, Resource: "assessment", Action: "execute", Scope: ScopeWorkspace, Description: "Trigger active security scanner execution", IsPrivileged: false},
	PermissionAssessmentCancel:  {Code: PermissionAssessmentCancel, Resource: "assessment", Action: "cancel", Scope: ScopeWorkspace, Description: "Abort or cancel running assessment jobs", IsPrivileged: false},
	PermissionAssessmentDelete:  {Code: PermissionAssessmentDelete, Resource: "assessment", Action: "delete", Scope: ScopeWorkspace, Description: "Delete historic assessment records", IsPrivileged: true},

	// Finding
	PermissionFindingRead:     {Code: PermissionFindingRead, Resource: "finding", Action: "read", Scope: ScopeWorkspace, Description: "Inspect vulnerability findings and timelines", IsPrivileged: false},
	PermissionFindingTriage:   {Code: PermissionFindingTriage, Resource: "finding", Action: "triage", Scope: ScopeWorkspace, Description: "Change triage state (Confirm, Resolve, In Progress)", IsPrivileged: false},
	PermissionFindingSuppress: {Code: PermissionFindingSuppress, Resource: "finding", Action: "suppress", Scope: ScopeWorkspace, Description: "Mark finding as False Positive or Accepted Risk", IsPrivileged: true},
	PermissionFindingExport:   {Code: PermissionFindingExport, Resource: "finding", Action: "export", Scope: ScopeWorkspace, Description: "Bulk export finding data to external formats", IsPrivileged: false},

	// Evidence
	PermissionEvidenceRead:       {Code: PermissionEvidenceRead, Resource: "evidence", Action: "read", Scope: ScopeWorkspace, Description: "View sanitized presentation-safe evidence", IsPrivileged: false},
	PermissionEvidenceDownload:   {Code: PermissionEvidenceDownload, Resource: "evidence", Action: "download", Scope: ScopeWorkspace, Description: "Download raw cryptographic evidence artifacts", IsPrivileged: true},
	PermissionEvidencePurge:      {Code: PermissionEvidencePurge, Resource: "evidence", Action: "purge", Scope: ScopeWorkspace, Description: "Permanently shred and purge evidence records", IsPrivileged: true},
	PermissionEvidenceHoldManage: {Code: PermissionEvidenceHoldManage, Resource: "evidence", Action: "hold:manage", Scope: ScopeWorkspace, Description: "Apply or remove legal retention holds on evidence", IsPrivileged: true},

	// Remediation
	PermissionRemediationRead:   {Code: PermissionRemediationRead, Resource: "remediation", Action: "read", Scope: ScopeWorkspace, Description: "View remediation tasks and SLA status", IsPrivileged: false},
	PermissionRemediationAssign: {Code: PermissionRemediationAssign, Resource: "remediation", Action: "assign", Scope: ScopeWorkspace, Description: "Assign remediation tasks and due dates", IsPrivileged: false},
	PermissionRemediationUpdate: {Code: PermissionRemediationUpdate, Resource: "remediation", Action: "update", Scope: ScopeWorkspace, Description: "Update task progress and add notes", IsPrivileged: false},
	PermissionRemediationVerify: {Code: PermissionRemediationVerify, Resource: "remediation", Action: "verify", Scope: ScopeWorkspace, Description: "Verify remediation fix via automated scan", IsPrivileged: false},

	// Report
	PermissionReportRead:     {Code: PermissionReportRead, Resource: "report", Action: "read", Scope: ScopeWorkspace, Description: "View report metadata and snapshot digests", IsPrivileged: false},
	PermissionReportGenerate: {Code: PermissionReportGenerate, Resource: "report", Action: "generate", Scope: ScopeWorkspace, Description: "Trigger HTML and PDF report generation", IsPrivileged: false},
	PermissionReportDownload: {Code: PermissionReportDownload, Resource: "report", Action: "download", Scope: ScopeWorkspace, Description: "Download cryptographically signed report files", IsPrivileged: false},
	PermissionReportExport:   {Code: PermissionReportExport, Resource: "report", Action: "export", Scope: ScopeWorkspace, Description: "Export executive compliance bundles", IsPrivileged: true},

	// Policy
	PermissionPolicyRead:             {Code: PermissionPolicyRead, Resource: "policy", Action: "read", Scope: ScopeOrganization, Description: "View enterprise security policies and rules", IsPrivileged: false},
	PermissionPolicyAdmin:            {Code: PermissionPolicyAdmin, Resource: "policy", Action: "admin", Scope: ScopeOrganization, Description: "Create and edit enterprise security policies", IsPrivileged: true},
	PermissionPolicySimulate:         {Code: PermissionPolicySimulate, Resource: "policy", Action: "simulate", Scope: ScopeOrganization, Description: "Simulate policy evaluation on past scans", IsPrivileged: false},
	PermissionPolicyExceptionApprove: {Code: PermissionPolicyExceptionApprove, Resource: "policy", Action: "exception:approve", Scope: ScopeOrganization, Description: "Approve temporary security policy exceptions", IsPrivileged: true},

	// Integration & Webhook
	PermissionIntegrationRead:      {Code: PermissionIntegrationRead, Resource: "integration", Action: "read", Scope: ScopeWorkspace, Description: "View configured integration connectors", IsPrivileged: false},
	PermissionIntegrationConfigure: {Code: PermissionIntegrationConfigure, Resource: "integration", Action: "configure", Scope: ScopeWorkspace, Description: "Configure Jira, GitHub, or SIEM connectors", IsPrivileged: true},
	PermissionWebhookManage:        {Code: PermissionWebhookManage, Resource: "webhook", Action: "manage", Scope: ScopeWorkspace, Description: "Manage outbound webhook endpoints and secret keys", IsPrivileged: true},

	// Audit
	PermissionAuditRead:   {Code: PermissionAuditRead, Resource: "audit", Action: "read", Scope: ScopeOrganization, Description: "Inspect immutable security audit log entries", IsPrivileged: true},
	PermissionAuditExport: {Code: PermissionAuditExport, Resource: "audit", Action: "export", Scope: ScopeOrganization, Description: "Export tamper-evident audit logs to SIEM/S3", IsPrivileged: true},
}

// AllPermissions returns a slice of all registered permissions.
func AllPermissions() []Permission {
	perms := make([]Permission, 0, len(catalog))
	for p := range catalog {
		perms = append(perms, p)
	}
	return perms
}

// GetPermissionMetadata returns the metadata for a given permission code.
func GetPermissionMetadata(p Permission) (*PermissionMetadata, bool) {
	meta, ok := catalog[p]
	if !ok {
		return nil, false
	}
	return &meta, true
}

// ValidatePermission checks whether a permission string is valid and registered.
func ValidatePermission(code Permission) error {
	if !permissionPattern.MatchString(string(code)) {
		return fmt.Errorf("%w: %q", ErrInvalidPermissionFormat, code)
	}
	if _, ok := catalog[code]; !ok {
		return fmt.Errorf("%w: %q", ErrUnregisteredPermission, code)
	}
	return nil
}

// IsPrivileged returns true if the permission represents a sensitive/privileged action.
func IsPrivileged(code Permission) bool {
	meta, ok := catalog[code]
	return ok && meta.IsPrivileged
}

// PermissionsByResource returns all permissions associated with a specific resource category.
func PermissionsByResource(resource string) []PermissionMetadata {
	var result []PermissionMetadata
	for _, meta := range catalog {
		if strings.EqualFold(meta.Resource, resource) {
			result = append(result, meta)
		}
	}
	return result
}
