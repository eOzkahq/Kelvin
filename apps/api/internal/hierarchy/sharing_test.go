package hierarchy

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestControlledResourceSharing(t *testing.T) {
	sharingRepo := NewMemorySharingRepository()
	hierarchyRepo := NewMemoryHierarchyRepository()
	auditMem := NewMemoryAuditRecorder()
	auditRecorder := NewHierarchyAuditRecorder(auditMem)
	hierarchySvc := NewHierarchyService(hierarchyRepo)
	sharingSvc := NewResourceSharingService(sharingRepo, hierarchyRepo, auditRecorder)
	ctx := context.Background()

	// 1. Setup Organization 1 with 2 Workspaces and a Team
	org1, _ := hierarchySvc.CreateOrganization(ctx, "Stark Industries", "stark", "user-tony")
	ws1, _ := hierarchySvc.CreateWorkspace(ctx, org1.ID, uuid.New(), "WS Alpha", "alpha", "production")
	ws2, _ := hierarchySvc.CreateWorkspace(ctx, org1.ID, uuid.New(), "WS Beta", "beta", "production")
	teamBeta, _ := hierarchySvc.CreateTeam(ctx, org1.ID, "user-tony", "Beta SecOps", "beta-secops", "Team for WS Beta")

	// Setup Organization 2 (competitor)
	org2, _ := hierarchySvc.CreateOrganization(ctx, "Hammer Industries", "hammer", "user-justin")
	wsHammer, _ := hierarchySvc.CreateWorkspace(ctx, org2.ID, uuid.New(), "Hammer WS", "hammer-ws", "production")

	// 2. Validate shareable resource types
	if err := ValidateShareableResourceType(ResourceTypeScanProfile); err != nil {
		t.Errorf("ScanProfile should be shareable: %v", err)
	}
	if err := ValidateShareableResourceType(ResourceTypeReport); err != nil {
		t.Errorf("Report should be shareable: %v", err)
	}
	if err := ValidateShareableResourceType(ShareableResourceType("RAW_EVIDENCE")); err != ErrResourceNotShareable {
		t.Errorf("RAW_EVIDENCE should NOT be shareable, got %v", err)
	}

	reportID := uuid.New()

	// 3. Reject Cross-Organization Sharing: sharing Stark report with Hammer workspace
	crossOrgGrant := &ResourceSharingGrant{
		OrganizationID:   org1.ID,
		ResourceType:     ResourceTypeReport,
		ResourceID:       reportID,
		SourceWorkspaceID: ws1.ID,
		TargetType:       "WORKSPACE",
		TargetID:         wsHammer.ID, // From Org 2!
		AccessLevel:      ShareAccessLevelRead,
		GrantedByUserID:  "user-tony",
	}
	err := sharingSvc.CreateSharingGrant(ctx, crossOrgGrant)
	if err != ErrCrossOrgSharingForbidden {
		t.Errorf("expected ErrCrossOrgSharingForbidden when sharing across organizations, got %v", err)
	}

	// 4. Create valid Sharing Grant within Org 1 (sharing report with Team Beta)
	validGrant := &ResourceSharingGrant{
		OrganizationID:   org1.ID,
		ResourceType:     ResourceTypeReport,
		ResourceID:       reportID,
		SourceWorkspaceID: ws1.ID,
		TargetType:       "TEAM",
		TargetID:         teamBeta.ID,
		AccessLevel:      ShareAccessLevelRead,
		GrantedByUserID:  "user-tony",
	}
	err = sharingSvc.CreateSharingGrant(ctx, validGrant)
	if err != nil {
		t.Fatalf("failed to create sharing grant: %v", err)
	}

	// 5. Authorize access for member of Team Beta
	err = sharingSvc.AuthorizeSharedResourceAccess(ctx, ResourceTypeReport, reportID, []uuid.UUID{teamBeta.ID}, ws2.ID, ShareAccessLevelRead)
	if err != nil {
		t.Errorf("member of teamBeta should have access to shared report: %v", err)
	}

	// Unrelated team has no access
	unrelatedTeamID := uuid.New()
	err = sharingSvc.AuthorizeSharedResourceAccess(ctx, ResourceTypeReport, reportID, []uuid.UUID{unrelatedTeamID}, ws2.ID, ShareAccessLevelRead)
	if err != ErrUnauthorized {
		t.Errorf("unrelated team should be unauthorized, got %v", err)
	}

	// 6. Revoke Sharing Grant
	err = sharingSvc.RevokeSharingGrant(ctx, validGrant.ID, "user-tony")
	if err != nil {
		t.Fatalf("failed to revoke sharing grant: %v", err)
	}

	// Subsequent access fails immediately
	err = sharingSvc.AuthorizeSharedResourceAccess(ctx, ResourceTypeReport, reportID, []uuid.UUID{teamBeta.ID}, ws2.ID, ShareAccessLevelRead)
	if err != ErrUnauthorized {
		t.Errorf("access after revocation should be unauthorized, got %v", err)
	}

	// 7. Verify audit events recorded
	expectedActions := []string{
		ActionResourceShared,
		ActionResourceUnshared,
	}

	var capturedActions []string
	for _, e := range auditMem.Events {
		if e.EntityType == "resource_sharing_grant" {
			capturedActions = append(capturedActions, e.Action)
		}
	}

	if len(capturedActions) != len(expectedActions) {
		t.Fatalf("expected %d sharing audit events, got %d", len(expectedActions), len(capturedActions))
	}

	for i, action := range expectedActions {
		if capturedActions[i] != action {
			t.Errorf("audit event %d action mismatch: got %s, want %s", i, capturedActions[i], action)
		}
	}
}
