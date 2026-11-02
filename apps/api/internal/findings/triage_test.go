package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateTriageDecisionRules(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	future := time.Now().UTC().Add(30 * 24 * time.Hour)
	past := time.Now().UTC().Add(-1 * time.Hour)
	canonicalID := uuid.New()

	// 1. Valid CONFIRMED
	validConfirmed := &TriageDecision{
		TenantID:      tenantID,
		FindingID:     findingID,
		Disposition:   DispositionConfirmed,
		Scope:         ScopePersistentFinding,
		Justification: "Confirmed reproduction in staging",
	}
	if err := ValidateTriageDecision(validConfirmed); err != nil {
		t.Errorf("expected valid confirmed decision, got %v", err)
	}

	// 2. Missing justification
	missingJustification := &TriageDecision{
		TenantID:    tenantID,
		FindingID:   findingID,
		Disposition: DispositionConfirmed,
	}
	if err := ValidateTriageDecision(missingJustification); err != ErrJustificationRequired {
		t.Errorf("expected ErrJustificationRequired, got %v", err)
	}

	// 3. Accepted risk without expiry
	noExpiry := &TriageDecision{
		TenantID:      tenantID,
		FindingID:     findingID,
		Disposition:   DispositionAcceptedRisk,
		Justification: "Accepted due to legacy system deprecation in Q4",
	}
	if err := ValidateTriageDecision(noExpiry); err != ErrExpiryRequired {
		t.Errorf("expected ErrExpiryRequired, got %v", err)
	}

	// 4. Accepted risk with past expiry
	pastExpiry := &TriageDecision{
		TenantID:      tenantID,
		FindingID:     findingID,
		Disposition:   DispositionAcceptedRisk,
		Justification: "Accepted risk",
		ExpiresAt:     &past,
	}
	if err := ValidateTriageDecision(pastExpiry); err == nil {
		t.Errorf("expected error on past expiration date")
	}

	// 5. Valid Accepted risk with future expiry
	validAccepted := &TriageDecision{
		TenantID:      tenantID,
		FindingID:     findingID,
		Disposition:   DispositionAcceptedRisk,
		Justification: "Approved exception per SecOps ticket SEC-991",
		ExpiresAt:     &future,
	}
	if err := ValidateTriageDecision(validAccepted); err != nil {
		t.Errorf("expected valid accepted risk decision, got %v", err)
	}

	// 6. Duplicate without canonical finding ID
	noCanonical := &TriageDecision{
		TenantID:      tenantID,
		FindingID:     findingID,
		Disposition:   DispositionDuplicate,
		Justification: "Duplicate of primary CORS alert",
	}
	if err := ValidateTriageDecision(noCanonical); err != ErrCanonicalIDRequired {
		t.Errorf("expected ErrCanonicalIDRequired, got %v", err)
	}

	// 7. Duplicate of self
	selfDup := &TriageDecision{
		TenantID:           tenantID,
		FindingID:          findingID,
		Disposition:        DispositionDuplicate,
		Justification:      "Self referential",
		CanonicalFindingID: &findingID,
	}
	if err := ValidateTriageDecision(selfDup); err != ErrSelfReferentialDuplicate {
		t.Errorf("expected ErrSelfReferentialDuplicate, got %v", err)
	}

	// 8. Valid duplicate
	validDup := &TriageDecision{
		TenantID:           tenantID,
		FindingID:          findingID,
		Disposition:        DispositionDuplicate,
		Justification:      "Duplicate of primary alert",
		CanonicalFindingID: &canonicalID,
	}
	if err := ValidateTriageDecision(validDup); err != nil {
		t.Errorf("expected valid duplicate decision, got %v", err)
	}
}

func TestTriageRepositoryValidation(t *testing.T) {
	repo := &PostgresFindingRepository{db: nil}
	ctx := context.Background()

	// Missing tenant on GetTriageDecisionsByFinding
	if _, err := repo.GetTriageDecisionsByFinding(ctx, uuid.Nil, uuid.New()); err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// Missing finding ID on GetTriageDecisionsByFinding
	if _, err := repo.GetTriageDecisionsByFinding(ctx, uuid.New(), uuid.Nil); err != ErrFindingIDRequired {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}
}
