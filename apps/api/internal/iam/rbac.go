package iam

import (
	"errors"
	"fmt"
)

// RoleName represents the standard identifier of a built-in enterprise role.
type RoleName string

const (
	RoleOrgOwner        RoleName = "ORG_OWNER"
	RoleOrgAdmin        RoleName = "ORG_ADMIN"
	RoleSecurityAdmin   RoleName = "SECURITY_ADMIN"
	RoleWorkspaceAdmin  RoleName = "WORKSPACE_ADMIN"
	RoleSecurityAnalyst RoleName = "SECURITY_ANALYST"
	RoleAuditor         RoleName = "AUDITOR"
	RoleReadOnlyViewer  RoleName = "READ_ONLY_VIEWER"
)

var (
	ErrRoleNotFound   = errors.New("built-in role not found in catalog")
	ErrPermissionDenied = errors.New("access denied: missing required permission")
)

// RoleDefinition describes a built-in role, its target scope, and granted permissions.
type RoleDefinition struct {
	Name        RoleName     `json:"name"`
	Scope       ScopeLevel   `json:"scope"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// builtInRoles defines the authoritative role-to-permission mapping for Kelvin.
var builtInRoles = map[RoleName]RoleDefinition{
	RoleOrgOwner: {
		Name:        RoleOrgOwner,
		Scope:       ScopeOrganization,
		Description: "Full administrative governance and root ownership across the organization and all workspaces",
		Permissions: []Permission{
			PermissionOrgRead, PermissionOrgAdmin, PermissionOrgSettingsWrite, PermissionOrgMembersManage,
			PermissionOrgBillingManage, PermissionOrgSSOManage,
			PermissionWorkspaceRead, PermissionWorkspaceCreate, PermissionWorkspaceAdmin, PermissionWorkspaceSettingsWrite,
			PermissionTeamRead, PermissionTeamCreate, PermissionTeamAdmin, PermissionTeamMembersManage,
			PermissionTargetRead, PermissionTargetCreate, PermissionTargetUpdate, PermissionTargetDelete,
			PermissionAssessmentRead, PermissionAssessmentCreate, PermissionAssessmentExecute, PermissionAssessmentCancel, PermissionAssessmentDelete,
			PermissionFindingRead, PermissionFindingTriage, PermissionFindingSuppress, PermissionFindingExport,
			PermissionEvidenceRead, PermissionEvidenceDownload, PermissionEvidencePurge, PermissionEvidenceHoldManage,
			PermissionRemediationRead, PermissionRemediationAssign, PermissionRemediationUpdate, PermissionRemediationVerify,
			PermissionReportRead, PermissionReportGenerate, PermissionReportDownload, PermissionReportExport,
			PermissionPolicyRead, PermissionPolicyAdmin, PermissionPolicySimulate, PermissionPolicyExceptionApprove,
			PermissionIntegrationRead, PermissionIntegrationConfigure, PermissionWebhookManage,
			PermissionAuditRead, PermissionAuditExport,
		},
	},

	RoleOrgAdmin: {
		Name:        RoleOrgAdmin,
		Scope:       ScopeOrganization,
		Description: "Delegated administrative governance of users, teams, SSO, policies, and workspace provisioning",
		Permissions: []Permission{
			PermissionOrgRead, PermissionOrgAdmin, PermissionOrgSettingsWrite, PermissionOrgMembersManage,
			PermissionOrgBillingManage, PermissionOrgSSOManage,
			PermissionWorkspaceRead, PermissionWorkspaceCreate, PermissionWorkspaceAdmin, PermissionWorkspaceSettingsWrite,
			PermissionTeamRead, PermissionTeamCreate, PermissionTeamAdmin, PermissionTeamMembersManage,
			PermissionPolicyRead, PermissionPolicyAdmin, PermissionPolicySimulate,
			PermissionAuditRead,
		},
	},

	RoleSecurityAdmin: {
		Name:        RoleSecurityAdmin,
		Scope:       ScopeOrganization,
		Description: "Cross-cutting enterprise security governance, policy exceptions, audit review, and compliance hold management",
		Permissions: []Permission{
			PermissionOrgRead, PermissionWorkspaceRead, PermissionTeamRead,
			PermissionPolicyRead, PermissionPolicyAdmin, PermissionPolicySimulate, PermissionPolicyExceptionApprove,
			PermissionEvidenceHoldManage, PermissionFindingSuppress, PermissionFindingExport,
			PermissionAuditRead, PermissionAuditExport,
			PermissionReportRead, PermissionReportGenerate, PermissionReportDownload, PermissionReportExport,
			PermissionRemediationRead, PermissionTargetRead, PermissionAssessmentRead, PermissionFindingRead,
		},
	},

	RoleWorkspaceAdmin: {
		Name:        RoleWorkspaceAdmin,
		Scope:       ScopeWorkspace,
		Description: "Full operational administration of a workspace, target assets, scan configurations, and team access",
		Permissions: []Permission{
			PermissionWorkspaceRead, PermissionWorkspaceAdmin, PermissionWorkspaceSettingsWrite,
			PermissionTargetRead, PermissionTargetCreate, PermissionTargetUpdate, PermissionTargetDelete,
			PermissionAssessmentRead, PermissionAssessmentCreate, PermissionAssessmentExecute, PermissionAssessmentCancel, PermissionAssessmentDelete,
			PermissionFindingRead, PermissionFindingTriage, PermissionFindingSuppress, PermissionFindingExport,
			PermissionEvidenceRead, PermissionEvidenceDownload, PermissionEvidencePurge,
			PermissionRemediationRead, PermissionRemediationAssign, PermissionRemediationUpdate, PermissionRemediationVerify,
			PermissionReportRead, PermissionReportGenerate, PermissionReportDownload, PermissionReportExport,
			PermissionIntegrationRead, PermissionIntegrationConfigure, PermissionWebhookManage,
		},
	},

	RoleSecurityAnalyst: {
		Name:        RoleSecurityAnalyst,
		Scope:       ScopeWorkspace,
		Description: "Day-to-day security operations: launching scans, triaging findings, updating remediation tasks, and generating reports",
		Permissions: []Permission{
			PermissionWorkspaceRead,
			PermissionTargetRead, PermissionTargetCreate, PermissionTargetUpdate,
			PermissionAssessmentRead, PermissionAssessmentCreate, PermissionAssessmentExecute, PermissionAssessmentCancel,
			PermissionFindingRead, PermissionFindingTriage, PermissionFindingExport,
			PermissionEvidenceRead,
			PermissionRemediationRead, PermissionRemediationAssign, PermissionRemediationUpdate, PermissionRemediationVerify,
			PermissionReportRead, PermissionReportGenerate, PermissionReportDownload,
		},
	},

	RoleAuditor: {
		Name:        RoleAuditor,
		Scope:       ScopeWorkspace,
		Description: "Read-only compliance audit access to findings, sanitized evidence, downloadable reports, and audit logs",
		Permissions: []Permission{
			PermissionOrgRead, PermissionWorkspaceRead,
			PermissionTargetRead, PermissionAssessmentRead,
			PermissionFindingRead, PermissionEvidenceRead, PermissionEvidenceDownload,
			PermissionRemediationRead,
			PermissionReportRead, PermissionReportDownload, PermissionReportExport,
			PermissionPolicyRead,
			PermissionAuditRead,
		},
	},

	RoleReadOnlyViewer: {
		Name:        RoleReadOnlyViewer,
		Scope:       ScopeWorkspace,
		Description: "Read-only observation of workspace security posture, finding dashboards, and assessment reports",
		Permissions: []Permission{
			PermissionWorkspaceRead,
			PermissionTargetRead, PermissionAssessmentRead,
			PermissionFindingRead, PermissionEvidenceRead,
			PermissionRemediationRead,
			PermissionReportRead, PermissionReportDownload,
		},
	},
}

// GetRoleDefinition looks up a built-in role definition.
func GetRoleDefinition(name RoleName) (*RoleDefinition, bool) {
	def, ok := builtInRoles[name]
	if !ok {
		return nil, false
	}
	return &def, true
}

// AllRoles returns all built-in role definitions.
func AllRoles() []RoleDefinition {
	roles := make([]RoleDefinition, 0, len(builtInRoles))
	for _, r := range builtInRoles {
		roles = append(roles, r)
	}
	return roles
}

// ResolveEffectivePermissions computes the deterministic set union of permissions across multiple assigned roles.
func ResolveEffectivePermissions(roles []RoleName) (map[Permission]bool, error) {
	effective := make(map[Permission]bool)
	for _, role := range roles {
		def, ok := builtInRoles[role]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrRoleNotFound, role)
		}
		for _, perm := range def.Permissions {
			effective[perm] = true
		}
	}
	return effective, nil
}

// HasPermission checks if the assigned roles collectively contain the required permission.
func HasPermission(roles []RoleName, perm Permission) bool {
	perms, err := ResolveEffectivePermissions(roles)
	if err != nil {
		return false
	}
	return perms[perm]
}

// RequirePermission verifies the assigned roles have the required permission, returning an error if missing.
func RequirePermission(roles []RoleName, perm Permission) error {
	if !HasPermission(roles, perm) {
		return fmt.Errorf("%w: required permission %q not granted by roles %v", ErrPermissionDenied, perm, roles)
	}
	return nil
}
