package iam

import (
	"testing"
)

func TestPermissionCatalogRegistrationAndFormat(t *testing.T) {
	allPerms := AllPermissions()
	if len(allPerms) == 0 {
		t.Fatalf("expected non-empty permission catalog")
	}

	seen := make(map[Permission]bool)
	for _, p := range allPerms {
		// 1. Verify no duplicate codes
		if seen[p] {
			t.Errorf("duplicate permission detected: %s", p)
		}
		seen[p] = true

		// 2. Verify format validation
		if err := ValidatePermission(p); err != nil {
			t.Errorf("permission %s failed validation: %v", p, err)
		}

		// 3. Verify metadata exists and has description
		meta, ok := GetPermissionMetadata(p)
		if !ok || meta == nil {
			t.Errorf("missing metadata for permission: %s", p)
			continue
		}
		if meta.Description == "" {
			t.Errorf("permission %s has empty description", p)
		}
		if meta.Resource == "" || meta.Action == "" {
			t.Errorf("permission %s has empty resource or action", p)
		}
	}
}

func TestValidatePermissionErrors(t *testing.T) {
	// Invalid format
	badFormats := []Permission{
		"invalid",
		"org:",
		":read",
		"ORG:READ",
		"org:read:123:456::",
		"",
	}
	for _, bf := range badFormats {
		if err := ValidatePermission(bf); err == nil {
			t.Errorf("expected error for malformed permission %q, got nil", bf)
		}
	}

	// Unregistered code
	unregistered := Permission("spaceship:launch")
	if err := ValidatePermission(unregistered); err == nil {
		t.Errorf("expected error for unregistered permission %q, got nil", unregistered)
	}
}

func TestPrivilegedFlagging(t *testing.T) {
	privilegedCases := []struct {
		perm       Permission
		privileged bool
	}{
		{PermissionOrgAdmin, true},
		{PermissionOrgSSOManage, true},
		{PermissionEvidencePurge, true},
		{PermissionEvidenceDownload, true},
		{PermissionPolicyExceptionApprove, true},
		{PermissionFindingRead, false},
		{PermissionAssessmentRead, false},
		{PermissionTargetRead, false},
		{PermissionRemediationRead, false},
	}

	for _, tc := range privilegedCases {
		if got := IsPrivileged(tc.perm); got != tc.privileged {
			t.Errorf("IsPrivileged(%s) = %v, want %v", tc.perm, got, tc.privileged)
		}
	}
}

func TestPermissionsByResource(t *testing.T) {
	findingsPerms := PermissionsByResource("finding")
	if len(findingsPerms) == 0 {
		t.Errorf("expected permissions for resource 'finding'")
	}

	for _, p := range findingsPerms {
		if p.Resource != "finding" {
			t.Errorf("expected resource 'finding', got %s", p.Resource)
		}
	}
}
