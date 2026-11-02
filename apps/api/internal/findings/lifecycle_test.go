package findings

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateTransitionPermittedRules(t *testing.T) {
	permitted := [][2]FindingStatus{
		// From NEW / OPEN
		{StatusNew, StatusConfirmed},
		{StatusNew, StatusFalsePositive},
		{StatusNew, StatusAcceptedRisk},
		{StatusNew, StatusInProgress},
		{StatusOpen, StatusConfirmed},
		{StatusOpen, StatusFalsePositive},
		{StatusOpen, StatusRiskAccepted},

		// From CONFIRMED
		{StatusConfirmed, StatusInProgress},
		{StatusConfirmed, StatusFalsePositive},
		{StatusConfirmed, StatusAcceptedRisk},
		{StatusConfirmed, StatusResolved},

		// From IN_PROGRESS
		{StatusInProgress, StatusResolved},
		{StatusInProgress, StatusConfirmed},

		// From RESOLVED
		{StatusResolved, StatusReopened},
		{StatusResolved, StatusInProgress},
		{StatusResolved, StatusNew},

		// From REOPENED
		{StatusReopened, StatusInProgress},
		{StatusReopened, StatusResolved},
		{StatusReopened, StatusConfirmed},

		// From FALSE_POSITIVE
		{StatusFalsePositive, StatusNew},
		{StatusFalsePositive, StatusOpen},

		// From ACCEPTED_RISK / RISK_ACCEPTED
		{StatusAcceptedRisk, StatusNew},
		{StatusAcceptedRisk, StatusResolved},
		{StatusRiskAccepted, StatusOpen},
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
		{StatusFalsePositive, StatusAcceptedRisk},
		{StatusAcceptedRisk, StatusFalsePositive},
		{StatusResolved, StatusFalsePositive},
		{StatusResolved, StatusAcceptedRisk},
		{StatusNew, StatusResolved}, // Must go through confirmation or progress
		{StatusOpen, StatusOpen},
		{StatusConfirmed, StatusConfirmed},
		{StatusResolved, StatusResolved},
	}

	for _, p := range prohibited {
		if err := ValidateTransition(p[0], p[1]); err == nil {
			t.Errorf("transition %s -> %s should be prohibited, but passed", p[0], p[1])
		}
	}
}

func TestAutomatedScannerTransitionPermissions(t *testing.T) {
	// Scanner can auto-reopen a resolved finding
	if err := ValidateTransitionWithActor(StatusResolved, StatusReopened, true); err != nil {
		t.Errorf("automated scanner should be allowed to auto-reopen RESOLVED findings, got: %v", err)
	}

	// Scanner CANNOT mark findings as FALSE_POSITIVE, CONFIRMED, or RESOLVED
	automatedForbidden := [][2]FindingStatus{
		{StatusNew, StatusConfirmed},
		{StatusNew, StatusFalsePositive},
		{StatusNew, StatusAcceptedRisk},
		{StatusConfirmed, StatusResolved},
		{StatusConfirmed, StatusFalsePositive},
	}

	for _, p := range automatedForbidden {
		if err := ValidateTransitionWithActor(p[0], p[1], true); err == nil {
			t.Errorf("automated transition %s -> %s should be forbidden for scanners, but passed", p[0], p[1])
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
	if finding.Status != StatusReopened {
		t.Errorf("expected auto-reopened status REOPENED, got %s", finding.Status)
	}
	if event.EventType != EventAutoReopened {
		t.Errorf("expected event AUTO_REOPENED, got %s", event.EventType)
	}
	if event.ToStatus != StatusReopened {
		t.Errorf("expected event ToStatus REOPENED, got %s", event.ToStatus)
	}
}

func TestIngestObservationPreservesAnalystTriageStates(t *testing.T) {
	tenantID := uuid.New()
	assessmentID := uuid.New()
	jobID := uuid.New()
	corrID := uuid.New()
	now := time.Now().UTC()

	analystStates := []FindingStatus{
		StatusConfirmed,
		StatusFalsePositive,
		StatusAcceptedRisk,
	}

	for _, state := range analystStates {
		finding := &PersistentFinding{
			ID:              uuid.New(),
			TenantID:        tenantID,
			ProjectID:       uuid.New(),
			AssessmentID:    assessmentID,
			JobID:           jobID,
			Fingerprint:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Title:           "Vulnerability Under Triage",
			Severity:        "MEDIUM",
			Status:          state,
			OccurrenceCount: 1,
			FirstSeenAt:     now,
			LastSeenAt:      now,
		}

		obs := FindingObservation{
			ID:           uuid.New(),
			TenantID:     tenantID,
			FindingID:    finding.ID,
			AssessmentID: assessmentID,
			JobID:        uuid.New(),
			ScannerID:    "zap",
			ObservedAt:   now.Add(time.Hour),
		}

		event, err := IngestObservation(finding, obs, corrID)
		if err != nil {
			t.Fatalf("IngestObservation failed on state %s: %v", state, err)
		}

		// Must preserve analyst decision
		if finding.Status != state {
			t.Errorf("finding status overwritten! Expected %s, got %s", state, finding.Status)
		}
		if finding.OccurrenceCount != 2 {
			t.Errorf("expected occurrence count 2, got %d", finding.OccurrenceCount)
		}
		if event.EventType != EventRedetected {
			t.Errorf("expected event REDETECTED, got %s", event.EventType)
		}
	}
}

func TestIngestObservationRejectsTenantMismatch(t *testing.T) {
	finding := &PersistentFinding{
		TenantID: uuid.New(),
	}
	obs := FindingObservation{
		TenantID: uuid.New(),
	}
	_, err := IngestObservation(finding, obs, uuid.New())
	if err == nil {
		t.Errorf("expected error on tenant mismatch")
	}
}
