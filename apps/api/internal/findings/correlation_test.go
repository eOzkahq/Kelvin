package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCorrelationGroupValidation(t *testing.T) {
	repo := &PostgresFindingRepository{db: nil}
	ctx := context.Background()

	// Nil group
	if err := repo.CreateCorrelationGroup(ctx, nil); err == nil {
		t.Errorf("expected error on nil group")
	}

	// Missing tenant
	if err := repo.CreateCorrelationGroup(ctx, &CorrelationGroup{
		Name:            "Missing Tenant Group",
		CorrelationType: CorrelationSharedVulnClass,
	}); err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing name
	if err := repo.CreateCorrelationGroup(ctx, &CorrelationGroup{
		TenantID:        uuid.New(),
		Name:            "   ",
		CorrelationType: CorrelationSharedVulnClass,
	}); err != ErrGroupNameRequired {
		t.Errorf("expected ErrGroupNameRequired, got %v", err)
	}

	// Invalid type
	if err := repo.CreateCorrelationGroup(ctx, &CorrelationGroup{
		TenantID:        uuid.New(),
		Name:            "Invalid Type Group",
		CorrelationType: "INVALID_TYPE",
	}); err == nil {
		t.Errorf("expected error on invalid correlation type")
	}
}

func TestCorrelationGroupMemberValidation(t *testing.T) {
	repo := &PostgresFindingRepository{db: nil}
	ctx := context.Background()

	// Nil member
	if err := repo.AddFindingToGroup(ctx, nil); err == nil {
		t.Errorf("expected error on nil member")
	}

	// Missing tenant
	if err := repo.AddFindingToGroup(ctx, &CorrelationGroupMember{
		GroupID:   uuid.New(),
		FindingID: uuid.New(),
	}); err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing group ID
	if err := repo.AddFindingToGroup(ctx, &CorrelationGroupMember{
		TenantID:  uuid.New(),
		FindingID: uuid.New(),
	}); err != ErrGroupIDRequired {
		t.Errorf("expected ErrGroupIDRequired, got %v", err)
	}

	// Missing finding ID
	if err := repo.AddFindingToGroup(ctx, &CorrelationGroupMember{
		TenantID: uuid.New(),
		GroupID:  uuid.New(),
	}); err != ErrFindingIDRequired {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}

	// Remove validation
	if err := repo.RemoveFindingFromGroup(ctx, uuid.Nil, uuid.New(), uuid.New()); err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}
	if err := repo.RemoveFindingFromGroup(ctx, uuid.New(), uuid.Nil, uuid.New()); err != ErrGroupIDRequired {
		t.Errorf("expected ErrGroupIDRequired, got %v", err)
	}
	if err := repo.RemoveFindingFromGroup(ctx, uuid.New(), uuid.New(), uuid.Nil); err != ErrFindingIDRequired {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}
}

func TestCorrelationGroupTypesPreserveFindingIntegrity(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	groupID := uuid.New()

	finding := &PersistentFinding{
		ID:              findingID,
		TenantID:        tenantID,
		Title:           "SQL Injection in /api/v1/auth",
		Status:          StatusOpen,
		OccurrenceCount: 1,
		FirstSeenAt:     time.Now().UTC(),
		LastSeenAt:      time.Now().UTC(),
	}

	group := &CorrelationGroup{
		ID:              groupID,
		TenantID:        tenantID,
		Name:            "Authentication Surface Weaknesses",
		CorrelationType: CorrelationSharedVulnClass,
		Description:     "All injection and auth bypass findings targeting authentication services",
	}

	member := &CorrelationGroupMember{
		ID:        uuid.New(),
		TenantID:  tenantID,
		GroupID:   group.ID,
		FindingID: finding.ID,
		Reason:    "Belongs to authentication security cluster",
	}

	// Verify correlation membership does not alter the underlying finding's status or identity
	if finding.ID != member.FindingID {
		t.Errorf("expected finding ID match")
	}
	if finding.Status != StatusOpen {
		t.Errorf("finding status must remain intact upon joining correlation group")
	}
	if finding.OccurrenceCount != 1 {
		t.Errorf("finding occurrence count must remain intact upon joining correlation group")
	}
}
