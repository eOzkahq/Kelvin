package findings

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIdentityResolverCreatesNewFindingOnFirstDetection(t *testing.T) {
	resolver := NewIdentityResolver()
	tenantID := uuid.New()
	projectID := uuid.New()
	assessmentID := uuid.New()
	jobID := uuid.New()
	corrID := uuid.New()

	input := ObservationInput{
		AssessmentID:   assessmentID,
		JobID:          jobID,
		ScannerID:      "nuclei",
		TargetAsset:    "target.example.com",
		TargetEndpoint: "https://target.example.com/login",
		TemplateID:     "cve-2021-44228",
		Title:          "Log4j RCE",
		Severity:       "CRITICAL",
		Confidence:     0.95,
		ObservedAt:     time.Now().UTC(),
	}

	result, err := resolver.Resolve(tenantID, projectID, input, nil, corrID)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if !result.IsNew {
		t.Errorf("expected IsNew = true")
	}
	if result.Finding.ID == uuid.Nil || result.Observation.ID == uuid.Nil {
		t.Errorf("expected non-nil IDs")
	}
	if result.Finding.ID == result.Observation.ID {
		t.Errorf("finding ID and observation ID must be distinct")
	}
	if result.Observation.FindingID != result.Finding.ID {
		t.Errorf("observation must reference parent finding ID")
	}
	if result.Finding.OccurrenceCount != 1 {
		t.Errorf("expected OccurrenceCount = 1")
	}
	if result.Event.EventType != EventCreated {
		t.Errorf("expected event CREATED, got %s", result.Event.EventType)
	}
}

func TestIdentityResolverLinksExistingFindingOnRedetection(t *testing.T) {
	resolver := NewIdentityResolver()
	tenantID := uuid.New()
	projectID := uuid.New()
	assessment1 := uuid.New()
	assessment2 := uuid.New()
	job1 := uuid.New()
	job2 := uuid.New()
	corrID := uuid.New()

	input1 := ObservationInput{
		AssessmentID:   assessment1,
		JobID:          job1,
		ScannerID:      "zap-baseline",
		TargetAsset:    "target.example.com",
		TargetEndpoint: "https://target.example.com/login",
		TemplateID:     "10020",
		Title:          "Missing Anti-clickjacking Header",
		Severity:       "MEDIUM",
		Confidence:     0.7,
		ObservedAt:     time.Now().UTC().Add(-2 * time.Hour),
	}

	// 1. Initial resolution (creates finding)
	res1, err := resolver.Resolve(tenantID, projectID, input1, nil, corrID)
	if err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}

	// 2. Second scan (Nuclei observing the same fingerprint on assessment2)
	input2 := ObservationInput{
		AssessmentID:   assessment2,
		JobID:          job2,
		ScannerID:      "nuclei",
		TargetAsset:    "target.example.com",
		TargetEndpoint: "https://target.example.com/login?token=ignored_in_fingerprint",
		TemplateID:     "10020",
		Title:          "Missing Anti-clickjacking Header (Nuclei)",
		Severity:       "MEDIUM",
		Confidence:     0.8,
		ObservedAt:     time.Now().UTC(),
	}

	res2, err := resolver.Resolve(tenantID, projectID, input2, []*PersistentFinding{res1.Finding}, corrID)
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}

	if res2.IsNew {
		t.Errorf("expected redetection to match existing finding, but got IsNew = true")
	}
	if res2.Finding.ID != res1.Finding.ID {
		t.Errorf("expected finding ID to match: %s != %s", res1.Finding.ID, res2.Finding.ID)
	}
	if res2.Finding.OccurrenceCount != 2 {
		t.Errorf("expected OccurrenceCount = 2, got %d", res2.Finding.OccurrenceCount)
	}
	if res2.Observation.ID == res1.Observation.ID {
		t.Errorf("observations must have distinct IDs")
	}
	if res2.Observation.ScannerID != "nuclei" || res1.Observation.ScannerID != "zap-baseline" {
		t.Errorf("each observation must preserve its distinct scanner provenance")
	}
}

func TestIdentityResolverStrictTenantAndProjectIsolation(t *testing.T) {
	resolver := NewIdentityResolver()
	tenantA := uuid.New()
	tenantB := uuid.New()
	projectA := uuid.New()
	projectB := uuid.New()
	corrID := uuid.New()

	input := ObservationInput{
		AssessmentID:   uuid.New(),
		JobID:          uuid.New(),
		ScannerID:      "nuclei",
		TargetAsset:    "shared.example.com",
		TargetEndpoint: "https://shared.example.com/api",
		TemplateID:     "sqli-api",
		Title:          "SQL Injection",
		Severity:       "HIGH",
		Confidence:     0.9,
	}

	// Resolve for Tenant A, Project A
	resA, err := resolver.Resolve(tenantA, projectA, input, nil, corrID)
	if err != nil {
		t.Fatal(err)
	}

	// Resolve for Tenant B with identical target & template -> MUST NOT match Tenant A
	resB, err := resolver.Resolve(tenantB, projectA, input, []*PersistentFinding{resA.Finding}, corrID)
	if err != nil {
		t.Fatal(err)
	}
	if resB.Finding.ID == resA.Finding.ID || !resB.IsNew {
		t.Errorf("cross-tenant finding merge detected! Findings must be tenant-isolated")
	}

	// Resolve for Tenant A, but Project B -> MUST NOT match Project A
	resProjB, err := resolver.Resolve(tenantA, projectB, input, []*PersistentFinding{resA.Finding}, corrID)
	if err != nil {
		t.Fatal(err)
	}
	if resProjB.Finding.ID == resA.Finding.ID || !resProjB.IsNew {
		t.Errorf("cross-project finding merge detected! Findings must be project-isolated")
	}
}
