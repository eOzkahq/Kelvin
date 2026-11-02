package iam

import (
	"testing"
)

func TestBuiltInRolesValidity(t *testing.T) {
	roles := AllRoles()
	if len(roles) == 0 {
		t.Fatalf("expected non-empty built-in roles")
	}

	for _, role := range roles {
		if role.Description == "" {
			t.Errorf("role %s has empty description", role.Name)
		}
		if len(role.Permissions) == 0 {
			t.Errorf("role %s has no assigned permissions", role.Name)
		}

		// Verify every permission is registered in the catalog
		for _, p := range role.Permissions {
			if err := ValidatePermission(p); err != nil {
				t.Errorf("role %s contains invalid permission %s: %v", role.Name, p, err)
			}
		}
	}
}

func TestResolveEffectivePermissionsUnion(t *testing.T) {
	// Combine SecurityAnalyst + Auditor
	roles := []RoleName{RoleSecurityAnalyst, RoleAuditor}
	perms, err := ResolveEffectivePermissions(roles)
	if err != nil {
		t.Fatalf("failed to resolve effective permissions: %v", err)
	}

	// Should have Analyst capability: assessment:execute
	if !perms[PermissionAssessmentExecute] {
		t.Errorf("expected PermissionAssessmentExecute from SecurityAnalyst")
	}

	// Should have Auditor capability: audit:read
	if !perms[PermissionAuditRead] {
		t.Errorf("expected PermissionAuditRead from Auditor")
	}

	// Neither role has evidence:purge
	if perms[PermissionEvidencePurge] {
		t.Errorf("neither role should have PermissionEvidencePurge")
	}
}

func TestRolePermissionEnforcement(t *testing.T) {
	tests := []struct {
		name       string
		roles      []RoleName
		permission Permission
		wantAllow  bool
	}{
		// Security Analyst
		{"Analyst can execute assessments", []RoleName{RoleSecurityAnalyst}, PermissionAssessmentExecute, true},
		{"Analyst can triage findings", []RoleName{RoleSecurityAnalyst}, PermissionFindingTriage, true},
		{"Analyst CANNOT purge evidence", []RoleName{RoleSecurityAnalyst}, PermissionEvidencePurge, false},
		{"Analyst CANNOT manage org members", []RoleName{RoleSecurityAnalyst}, PermissionOrgMembersManage, false},

		// Read Only Viewer
		{"Viewer can read findings", []RoleName{RoleReadOnlyViewer}, PermissionFindingRead, true},
		{"Viewer CANNOT triage findings", []RoleName{RoleReadOnlyViewer}, PermissionFindingTriage, false},
		{"Viewer CANNOT execute assessments", []RoleName{RoleReadOnlyViewer}, PermissionAssessmentExecute, false},

		// Auditor
		{"Auditor can read audit log", []RoleName{RoleAuditor}, PermissionAuditRead, true},
		{"Auditor can download evidence", []RoleName{RoleAuditor}, PermissionEvidenceDownload, true},
		{"Auditor CANNOT create assessments", []RoleName{RoleAuditor}, PermissionAssessmentCreate, false},

		// Org Owner
		{"Owner has full permissions", []RoleName{RoleOrgOwner}, PermissionOrgSSOManage, true},
		{"Owner can purge evidence", []RoleName{RoleOrgOwner}, PermissionEvidencePurge, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := HasPermission(tt.roles, tt.permission)
			if allowed != tt.wantAllow {
				t.Errorf("HasPermission(%v, %s) = %v, want %v", tt.roles, tt.permission, allowed, tt.wantAllow)
			}

			err := RequirePermission(tt.roles, tt.permission)
			if tt.wantAllow && err != nil {
				t.Errorf("RequirePermission should succeed, got %v", err)
			}
			if !tt.wantAllow && err == nil {
				t.Errorf("RequirePermission should fail, got nil")
			}
		})
	}
}

func TestUnknownRoleError(t *testing.T) {
	_, err := ResolveEffectivePermissions([]RoleName{"SUPER_USER_UNKNOWN"})
	if err == nil {
		t.Errorf("expected error for unknown role, got nil")
	}
}
