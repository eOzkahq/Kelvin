package findings

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateTransitionPermittedRules(t *testing.T) {
	permitted := [][2]FindingStatus{
		{StatusOpen, StatusConfirmed},
		{StatusOpen, StatusFalsePositive},
		{StatusOpen, StatusRiskAccepted},
		{StatusOpen, StatusResolved},
		{StatusConfirmed, StatusResolved},
		{StatusConfirmed, StatusFalsePositive},
		{StatusConfirmed, StatusRiskAccepted},
		{StatusConfirmed, StatusOpen},
		{StatusResolved, StatusOpen},
		{StatusResolved, StatusConfirmed},
		{StatusRiskAccepted, StatusOpen},
		{StatusRiskAccepted, StatusConfirmed},
		{StatusFalsePositive, StatusOpen},
	}

	for _, p := range permitted {
		if err := ValidateTransition(p[0], p[1]); err != nil {
			t.Errorf("transition %s -> %s should be permitted, got error: %v", p[0], p[1], err)
		}
	}
}

func TestValidateTransitionProhibitedRules(t *testing.T) {
	prohibited := [][2]FindingStatus{
		{StatusFalsePositive, StatusResolved},
		{StatusFalsePositive, StatusRiskAccepted},
		{StatusRiskAccepted, StatusFalsePositive},
		{StatusResolved, StatusFalsePositive},
		{StatusResolved, StatusRiskAccepted},
		{StatusOpen, StatusOpen},
		{StatusConfirmed, StatusConfirmed},
	}

	for _, p := range prohibited {
		if err := ValidateTransition(p[0], p[1]); err == nil {
			t.Errorf("transition %s -> %s should be prohibited, but passed", p[0], p[1])
		}
	}
}

func TestIngestObservationUpdatesAndAutoReopens(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	assessmentID := uuid.New()
	job1 := uuid.New()
	job2 := uuid.New()
	corrID := uuid.New()

	now := time.Now().UTC()

	// Initial finding state: RESOLVED
	finding := &PersistentFinding{
		ID:              findingID,
		TenantID:        tenantID,
		ProjectID:       uuid.New(),
		AssessmentID:    assessmentID,
		JobID:           job1,
		Fingerprint:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Title:           "SQL Injection in Search Form",
		Severity:        "HIGH",
		Confidence:      0.9,
		Status:          StatusResolved,
		OccurrenceCount: 1,
		FirstSeenAt:     now.Add(-24 * time.Hour),
		LastSeenAt:      now.Add(-24 * time.Hour),
		FirstJobID:      job1,
	}

	obs := FindingObservation{
		ID:           uuid.New(),
		TenantID:     tenantID,
		FindingID:    findingID,
		AssessmentID: assessmentID,
		JobID:        job2,
		ScannerID:    "nuclei",
		ObservedAt:   now,
	}

	event, err := IngestObservation(finding, obs, corrID)
	if err != nil {
		t.Fatalf("IngestObservation failed: %v", err)
	}

	if finding.OccurrenceCount != 2 {
		t.Errorf("expected occurrence count 2, got %d", finding.OccurrenceCount)
	}
	if finding.Status != StatusOpen {
		t.Errorf("expected auto-reopened status OPEN, got %s", finding.Status)
	}
	if event.EventType != EventAutoReopened {
		t.Errorf("expected event AUTO_REOPENED, got %s", event.EventType)
	}
	if *finding.LastJobID != job2 {
		t.Errorf("expected last job ID %s, got %s", job2, *finding.LastJobID)
	}
}

func TestIngestObservationRejectsTenantMismatch(t *testing.T) {
	finding := &PersistentFinding{
		ID:       uuid.New(),
		TenantID: uuid.New(),
	}

	obs := FindingObservation{
		ID:       uuid.New(),
		TenantID: uuid.New(), // different tenant
	}

	if _, err := IngestObservation(finding, obs, uuid.New()); err == nil {
		t.Fatal("expected error on tenant mismatch, but passed")
	}
}
