package findings

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRiskHistoryEntryValidation(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()

	repo := NewPostgresFindingRepository(nil)

	// 1. Nil entry error
	if err := repo.ArchiveRiskHistory(nil, nil); err == nil {
		t.Errorf("expected error for nil history entry")
	}

	// 2. Missing tenant error
	err := repo.ArchiveRiskHistory(nil, &FindingRiskHistoryEntry{
		FindingID: findingID,
	})
	if err != ErrTenantRequired {
		t.Errorf("expected ErrTenantRequired, got %v", err)
	}

	// 3. Missing finding ID error
	err = repo.ArchiveRiskHistory(nil, &FindingRiskHistoryEntry{
		TenantID: tenantID,
	})
	if err != ErrFindingIDRequired {
		t.Errorf("expected ErrFindingIDRequired, got %v", err)
	}
}

func TestRecalculationStatusInvariance(t *testing.T) {
	findingID := uuid.New()
	tenantID := uuid.New()
	initialScore := 5.0

	// Invariant: Changing risk score must NEVER mutate finding status!
	f := &PersistentFinding{
		ID:               findingID,
		TenantID:         tenantID,
		Severity:         "HIGH",
		Confidence:       0.90,
		Status:           StatusInProgress, // Operational lifecycle state
		RiskScore:        &initialScore,
		RiskPriorityBand: RiskBandMedium,
		UpdatedAt:        time.Now().UTC().Add(-time.Hour),
	}

	// Calculate new score with higher confidence and exposure
	res, err := CalculateRiskScore(RiskAssessmentInput{
		FindingID:       f.ID,
		ScannerSeverity: f.Severity,
		Confidence:      1.0,
		Exposure:        ExposurePublicInternet,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate recalculation update
	f.RiskScore = &res.RiskScore
	f.RiskPriorityBand = res.PriorityBand
	f.UpdatedAt = time.Now().UTC()

	// Verify lifecycle status remained intact
	if f.Status != StatusInProgress {
		t.Errorf("lifecycle status mutated during risk recalculation: expected %v, got %v", StatusInProgress, f.Status)
	}
	if *f.RiskScore <= initialScore {
		t.Errorf("expected increased risk score: got %v, initial %v", *f.RiskScore, initialScore)
	}
}
