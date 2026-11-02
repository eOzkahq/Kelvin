package hierarchy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOrganizationLifecycleTransitions(t *testing.T) {
	repo := NewMemoryHierarchyRepository()
	auditMem := NewMemoryAuditRecorder()
	auditRecorder := NewHierarchyAuditRecorder(auditMem)
	svc := NewHierarchyService(repo).WithAuditRecorder(auditRecorder)
	ctx := context.Background()

	// 1. Create Organization (creator is OWNER)
	org, err := svc.CreateOrganization(ctx, "Stark Industries", "stark-industries", "user-tony")
	if err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}

	if org.Status != OrgStateActive {
		t.Fatalf("expected initial status ACTIVE, got %s", org.Status)
	}

	// 2. Add an ADMIN and a regular MEMBER
	adminID := "user-rhodey"
	memberID := "user-peter"

	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         adminID,
		Role:           OrgRoleAdmin,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	_ = repo.SaveOrgMembership(ctx, &OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         memberID,
		Role:           OrgRoleMember,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// 3. Regular member cannot suspend organization
	err = svc.SuspendOrganization(ctx, org.ID, memberID, "Non-payment")
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for regular member suspending org, got %v", err)
	}

	// 4. Admin suspends organization
	err = svc.SuspendOrganization(ctx, org.ID, adminID, "Billing compliance review")
	if err != nil {
		t.Fatalf("admin failed to suspend organization: %v", err)
	}

	updatedOrg, _ := repo.GetOrganization(ctx, org.ID)
	if updatedOrg.Status != OrgStateSuspended {
		t.Errorf("expected status SUSPENDED, got %s", updatedOrg.Status)
	}
	if updatedOrg.SuspensionReason != "Billing compliance review" {
		t.Errorf("expected reason 'Billing compliance review', got %s", updatedOrg.SuspensionReason)
	}

	// 5. Create a workspace under this org and verify EnsureWorkspaceOperational blocks operations
	ws, err := repo.GetWorkspaceByTenantID(ctx, uuid.New())
	// Create workspace directly in repo to test operational check
	ws = &Workspace{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		TenantID:       uuid.New(),
		Name:           "Lab Workspace",
		Slug:           "lab",
		Environment:    "production",
		Status:         "ACTIVE",
	}
	_ = repo.CreateWorkspace(ctx, ws)

	err = svc.EnsureWorkspaceOperational(ctx, ws.ID)
	if err != ErrOrgSuspended {
		t.Errorf("expected ErrOrgSuspended, got %v", err)
	}

	// 6. Cannot create new workspace while org is suspended
	_, err = svc.CreateWorkspace(ctx, org.ID, uuid.New(), "New WS", "new-ws", "staging")
	if err != ErrOrgSuspended {
		t.Errorf("expected ErrOrgSuspended on CreateWorkspace, got %v", err)
	}

	// 7. Reactivate organization
	err = svc.ReactivateOrganization(ctx, org.ID, adminID)
	if err != nil {
		t.Fatalf("failed to reactivate organization: %v", err)
	}

	updatedOrg, _ = repo.GetOrganization(ctx, org.ID)
	if updatedOrg.Status != OrgStateActive {
		t.Errorf("expected status ACTIVE, got %s", updatedOrg.Status)
	}
	if updatedOrg.SuspendedAt != nil {
		t.Errorf("expected SuspendedAt to be nil after reactivation")
	}

	// Workspace is now operational again
	err = svc.EnsureWorkspaceOperational(ctx, ws.ID)
	if err != nil {
		t.Errorf("expected workspace to be operational after reactivation, got %v", err)
	}

	// 8. Request deletion (Admin cannot, only Owner can)
	err = svc.RequestOrganizationDeletion(ctx, org.ID, adminID, 14*24*time.Hour)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized when Admin attempts deletion request, got %v", err)
	}

	// Owner requests deletion
	err = svc.RequestOrganizationDeletion(ctx, org.ID, "user-tony", 14*24*time.Hour)
	if err != nil {
		t.Fatalf("owner failed to request deletion: %v", err)
	}

	updatedOrg, _ = repo.GetOrganization(ctx, org.ID)
	if updatedOrg.Status != OrgStatePendingDeletion {
		t.Errorf("expected status PENDING_DELETION, got %s", updatedOrg.Status)
	}

	// 9. Cancel deletion
	err = svc.CancelOrganizationDeletion(ctx, org.ID, "user-tony")
	if err != nil {
		t.Fatalf("failed to cancel deletion: %v", err)
	}

	updatedOrg, _ = repo.GetOrganization(ctx, org.ID)
	if updatedOrg.Status != OrgStateActive {
		t.Errorf("expected status ACTIVE after cancellation, got %s", updatedOrg.Status)
	}

	// 10. Verify audit events recorded
	expectedActions := []string{
		ActionOrgCreated,
		ActionOrgSuspended,
		ActionOrgReactivated,
		ActionOrgDeletionRequested,
		ActionOrgReactivated,
	}

	if len(auditMem.Events) != len(expectedActions) {
		t.Fatalf("expected %d audit events, got %d", len(expectedActions), len(auditMem.Events))
	}

	for i, action := range expectedActions {
		if auditMem.Events[i].Action != action {
			t.Errorf("audit event %d action mismatch: got %s, want %s", i, auditMem.Events[i].Action, action)
		}
	}
}

func TestValidateOrgStateTransitionRules(t *testing.T) {
	// Active -> Suspended: OK
	if err := ValidateOrgStateTransition(OrgStateActive, OrgStateSuspended); err != nil {
		t.Errorf("Active -> Suspended should be valid: %v", err)
	}

	// Suspended -> Active: OK
	if err := ValidateOrgStateTransition(OrgStateSuspended, OrgStateActive); err != nil {
		t.Errorf("Suspended -> Active should be valid: %v", err)
	}

	// Purged -> Active: Invalid
	if err := ValidateOrgStateTransition(OrgStatePurged, OrgStateActive); err == nil {
		t.Errorf("Purged -> Active should be rejected")
	}

	// Idempotent Active -> Active: OK
	if err := ValidateOrgStateTransition(OrgStateActive, OrgStateActive); err != nil {
		t.Errorf("Active -> Active idempotent transition should be valid: %v", err)
	}
}
