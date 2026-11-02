package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestScanProfileService_LifecycleAndApproval(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryScanProfileRepository()
	mockAudit := &mockAuditRecorder{}
	service := NewScanProfileService(repo, mockAudit)

	orgID := uuid.New()
	authorID := "usr_security_engineer"
	approverID := "usr_secops_director"

	profileReq := &ScanProfile{
		OrganizationID: orgID,
		Name:           "PCI Aggressive Deep Scan",
		Slug:           "pci-deep-scan",
		Description:    "Aggressive web and network scans for PCI compliance",
		Scanners:       []string{"zap", "nuclei"},
		Intensity:      "AGGRESSIVE",
	}

	created, err := service.CreateProfile(ctx, authorID, profileReq)
	if err != nil {
		t.Fatalf("unexpected error creating profile: %v", err)
	}

	t.Run("profile starts in DRAFT and aggressive intensity mandates approval", func(t *testing.T) {
		if created.State != ProfileStateDraft {
			t.Errorf("expected state DRAFT, got %s", created.State)
		}
		if !created.RequiresApproval {
			t.Errorf("expected AGGRESSIVE scan profile to require approval")
		}
		if created.Version != 1 {
			t.Errorf("expected version 1, got %d", created.Version)
		}

		// Draft profile cannot be used for scan execution
		err := service.ValidateProfileUsable(ctx, created.ID)
		if !errors.Is(err, ErrProfileNotUsable) {
			t.Fatalf("expected ErrProfileNotUsable for draft profile, got %v", err)
		}
	})

	t.Run("submit profile for approval", func(t *testing.T) {
		submitted, err := service.SubmitForApproval(ctx, authorID, created.ID)
		if err != nil {
			t.Fatalf("unexpected error submitting for approval: %v", err)
		}
		if submitted.State != ProfileStatePendingApproval {
			t.Errorf("expected state PENDING_APPROVAL, got %s", submitted.State)
		}
	})

	t.Run("self-approval defense: author cannot approve own profile", func(t *testing.T) {
		_, err := service.ApproveProfile(ctx, authorID, created.ID)
		if !errors.Is(err, ErrSelfApprovalProhibited) {
			t.Fatalf("expected ErrSelfApprovalProhibited, got %v", err)
		}
	})

	t.Run("approver approves profile and creates immutable snapshot", func(t *testing.T) {
		approved, err := service.ApproveProfile(ctx, approverID, created.ID)
		if err != nil {
			t.Fatalf("unexpected error approving profile: %v", err)
		}
		if approved.State != ProfileStateApproved {
			t.Errorf("expected state APPROVED, got %s", approved.State)
		}
		if approved.ApprovedByUserID != approverID || approved.ApprovedAt == nil {
			t.Errorf("expected approver details recorded")
		}

		// Verify snapshot was created for version 1
		snap, err := repo.GetSnapshot(ctx, created.ID, 1)
		if err != nil {
			t.Fatalf("failed to retrieve version 1 snapshot: %v", err)
		}
		if snap.Spec["slug"] != "pci-deep-scan" {
			t.Errorf("expected snapshot slug pci-deep-scan")
		}
	})

	t.Run("activate profile and verify usable", func(t *testing.T) {
		activated, err := service.ActivateProfile(ctx, approverID, created.ID)
		if err != nil {
			t.Fatalf("unexpected error activating profile: %v", err)
		}
		if activated.State != ProfileStateActive {
			t.Errorf("expected state ACTIVE, got %s", activated.State)
		}

		err = service.ValidateProfileUsable(ctx, created.ID)
		if err != nil {
			t.Fatalf("expected active profile to be usable, got error: %v", err)
		}
	})

	t.Run("updating spec increments version to DRAFT and preserves prior snapshot", func(t *testing.T) {
		newScanners := []string{"zap", "nuclei", "tls"}
		newConfig := map[string]any{"threads": 10}

		updated, err := service.UpdateSpec(ctx, authorID, created.ID, newScanners, newConfig)
		if err != nil {
			t.Fatalf("failed to update spec: %v", err)
		}
		if updated.Version != 2 {
			t.Errorf("expected version 2, got %d", updated.Version)
		}
		if updated.State != ProfileStateDraft {
			t.Errorf("expected updated profile to revert to DRAFT, got %s", updated.State)
		}

		// Historical snapshot of version 1 is still intact
		snap1, err := repo.GetSnapshot(ctx, created.ID, 1)
		if err != nil || snap1.Version != 1 {
			t.Fatalf("expected version 1 snapshot to remain intact")
		}
	})

	t.Run("retiring profile blocks future use", func(t *testing.T) {
		// Create and approve another profile
		p2, _ := service.CreateProfile(ctx, authorID, &ScanProfile{
			OrganizationID: orgID,
			Name:           "Profile 2",
			Slug:           "profile-2",
			Intensity:      "NORMAL",
		})
		_, _ = service.SubmitForApproval(ctx, authorID, p2.ID)
		_, _ = service.ApproveProfile(ctx, approverID, p2.ID)
		_, _ = service.ActivateProfile(ctx, approverID, p2.ID)

		retired, err := service.RetireProfile(ctx, approverID, p2.ID)
		if err != nil {
			t.Fatalf("unexpected error retiring profile: %v", err)
		}
		if retired.State != ProfileStateRetired {
			t.Errorf("expected state RETIRED, got %s", retired.State)
		}

		err = service.ValidateProfileUsable(ctx, p2.ID)
		if !errors.Is(err, ErrProfileRetired) {
			t.Fatalf("expected ErrProfileRetired, got %v", err)
		}
	})
}
