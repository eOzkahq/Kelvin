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

func TestIdentityResolverAmbiguousLocationHandledAsDistinct(t *testing.T) {
	resolver := NewIdentityResolver()
	tenantID := uuid.New()
	projectID := uuid.New()
	corrID := uuid.New()

	input1 := ObservationInput{
		AssessmentID:   uuid.New(),
		JobID:          uuid.New(),
		ScannerID:      "zap",
		TargetAsset:    "api.example.com",
		TargetEndpoint: "https://api.example.com/v1/users",
		TemplateID:     "sqli-rule",
		Title:          "SQL Injection",
		Severity:       "HIGH",
	}

	res1, err := resolver.Resolve(tenantID, projectID, input1, nil, corrID)
	if err != nil {
		t.Fatal(err)
	}

	// Same asset and template, but distinct endpoint (/v2/orders)
	input2 := ObservationInput{
		AssessmentID:   uuid.New(),
		JobID:          uuid.New(),
		ScannerID:      "nuclei",
		TargetAsset:    "api.example.com",
		TargetEndpoint: "https://api.example.com/v2/orders",
		TemplateID:     "sqli-rule",
		Title:          "SQL Injection",
		Severity:       "HIGH",
	}

	res2, err := resolver.Resolve(tenantID, projectID, input2, []*PersistentFinding{res1.Finding}, corrID)
	if err != nil {
		t.Fatal(err)
	}

	// Must NOT be merged into res1. Must be a distinct new finding.
	if res2.Finding.ID == res1.Finding.ID {
		t.Errorf("ambiguous identity should not merge into existing finding")
	}
	if !res2.IsNew {
		t.Errorf("res2 should be marked IsNew")
	}
	if !res2.IsAmbiguous {
		t.Errorf("res2 should be marked IsAmbiguous due to overlapping asset/rule but differing endpoint")
	}
	if res2.Algorithm != "v1" {
		t.Errorf("expected algorithm v1, got %s", res2.Algorithm)
	}
}

func TestCrossAssessmentDynamicPathRecurrence(t *testing.T) {
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
		ScannerID:      "nuclei",
		TargetAsset:    "api.example.com",
		TargetEndpoint: "https://api.example.com/api/v1/users/1001/profile",
		TemplateID:     "idor-rule",
		Title:          "IDOR Profile Access",
		Severity:       "HIGH",
		ObservedAt:     time.Now().UTC().Add(-2 * time.Hour),
	}

	res1, err := resolver.Resolve(tenantID, projectID, input1, nil, corrID)
	if err != nil {
		t.Fatal(err)
	}

	// Assessment 2 scans a different dynamic user ID
	input2 := ObservationInput{
		AssessmentID:   assessment2,
		JobID:          job2,
		ScannerID:      "nuclei",
		TargetAsset:    "api.example.com",
		TargetEndpoint: "https://api.example.com/api/v1/users/2002/profile",
		TemplateID:     "idor-rule",
		Title:          "IDOR Profile Access",
		Severity:       "HIGH",
		ObservedAt:     time.Now().UTC(),
	}

	res2, err := resolver.Resolve(tenantID, projectID, input2, []*PersistentFinding{res1.Finding}, corrID)
	if err != nil {
		t.Fatal(err)
	}

	if res2.IsNew {
		t.Errorf("expected dynamic path finding to be matched as recurrent, but was treated as new")
	}
	if res2.Finding.ID != res1.Finding.ID {
		t.Errorf("expected observation to bind to existing finding ID %s, got %s", res1.Finding.ID, res2.Finding.ID)
	}
	if res2.Algorithm != "v1-dynamic-path" {
		t.Errorf("expected algorithm v1-dynamic-path, got %s", res2.Algorithm)
	}
	if res2.MatchConfidence < 0.9 {
		t.Errorf("expected match confidence >= 0.9, got %f", res2.MatchConfidence)
	}
	if res2.Finding.OccurrenceCount != 2 {
		t.Errorf("expected occurrence count 2, got %d", res2.Finding.OccurrenceCount)
	}
}
