package findings

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

func TestSameAssessmentDeduplicatorIdenticalResults(t *testing.T) {
	dedup := NewInAssessmentDeduplicator()

	finding1 := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com/api/v1/login",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "cve-2023-1234",
			CVEIDs:     []string{"CVE-2023-1234"},
			CWEID:      "CWE-89",
		},
		Title:    "SQL Injection in Login Endpoint",
		Severity: "HIGH",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
		Evidence: []normalization.Evidence{
			{
				Type:            "http_request_response",
				ContentRedacted: "' OR 1=1 --",
			},
		},
		Tags: []string{"sqli", "owasp-top-10"},
	}

	finding2 := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com/api/v1/login",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "cve-2023-1234",
			CVEIDs:     []string{"CVE-2023-1234"},
			CWEID:      "CWE-89",
		},
		Title:    "SQL Injection in Login Endpoint",
		Severity: "HIGH",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
		Evidence: []normalization.Evidence{
			{
				Type:            "http_request_response",
				ContentRedacted: "admin' --",
			},
		},
		Tags: []string{"sqli", "login"},
	}

	results, decisions, err := dedup.Deduplicate([]normalization.CanonicalFinding{finding1, finding2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(results))
	}

	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}

	if decisions[0].Action != ActionMergeSameAssessment {
		t.Errorf("expected ActionMergeSameAssessment, got %v", decisions[0].Action)
	}

	// Verify evidence merged
	if len(results[0].Evidence) != 2 {
		t.Errorf("expected 2 merged evidence entries, got %d", len(results[0].Evidence))
	}

	// Verify tags merged
	if len(results[0].Tags) != 3 { // login, owasp-top-10, sqli
		t.Errorf("expected 3 merged unique tags, got %d", len(results[0].Tags))
	}
}

func TestSameAssessmentDeduplicatorCrossScannerMerge(t *testing.T) {
	dedup := NewInAssessmentDeduplicator()

	nucleiFinding := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "example.com",
			Endpoint: "https://example.com/sensitive-data",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "cors-misconfig",
			CWEID:      "CWE-942",
		},
		Title:    "Overly Permissive CORS Policy",
		Severity: "MEDIUM",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
		Evidence: []normalization.Evidence{
			{Type: "raw", ContentRedacted: "Origin: evil.com"},
		},
	}

	zapFinding := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "example.com",
			Endpoint: "https://example.com/sensitive-data",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "cors-misconfig",
			CWEID:      "CWE-942",
		},
		Title:    "Overly Permissive CORS Policy",
		Severity: "MEDIUM",
		Scanner: normalization.ScannerInfo{
			Name: "owasp-zap",
		},
		Evidence: []normalization.Evidence{
			{Type: "raw", ContentRedacted: "Access-Control-Allow-Origin: *"},
		},
	}

	results, decisions, err := dedup.Deduplicate([]normalization.CanonicalFinding{nucleiFinding, zapFinding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(results))
	}

	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}

	if decisions[0].Action != ActionMergeSameAssessment {
		t.Errorf("expected ActionMergeSameAssessment, got %v", decisions[0].Action)
	}

	if len(decisions[0].SecondaryScanners) != 1 || decisions[0].SecondaryScanners[0] != "owasp-zap" {
		t.Errorf("expected secondary scanner owasp-zap, got %v", decisions[0].SecondaryScanners)
	}

	if len(results[0].Evidence) != 2 {
		t.Errorf("expected 2 merged evidence entries from both scanners, got %d", len(results[0].Evidence))
	}
}

func TestSameAssessmentDeduplicatorDistinctLocationsKeptSeparate(t *testing.T) {
	dedup := NewInAssessmentDeduplicator()

	findingA := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com/api/v1/auth",
		},
		Vulnerability: normalization.Vulnerability{
			CWEID: "CWE-89",
		},
		Title:    "SQL Injection",
		Severity: "HIGH",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
	}

	findingB := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com/api/v1/profile",
		},
		Vulnerability: normalization.Vulnerability{
			CWEID: "CWE-89",
		},
		Title:    "SQL Injection",
		Severity: "HIGH",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
	}

	results, decisions, err := dedup.Deduplicate([]normalization.CanonicalFinding{findingA, findingB})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 distinct findings, got %d", len(results))
	}

	for _, d := range decisions {
		if d.Action != ActionCreateDistinct {
			t.Errorf("expected ActionCreateDistinct for different endpoints, got %v", d.Action)
		}
	}
}

func TestIngestBatchSameAssessmentDeduplicationIntegration(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	assessmentID := uuid.New()
	jobID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			assessmentID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: assessmentID,
				JobID:        jobID,
				Status:       "COMPLETED",
				TargetAsset:  "example.com",
			},
		},
	}

	repo := &mockFindingRepo{
		findings:     make(map[uuid.UUID]*PersistentFinding),
		observations: make(map[uuid.UUID]*FindingObservation),
		events:       make(map[uuid.UUID]*FindingEvent),
	}
	publisher := &mockEventPublisher{}

	svc := NewIngestionService(validator, repo, publisher)

	rawFindings := []normalization.CanonicalFinding{
		{
			Target: normalization.Target{
				Asset:    "example.com",
				Endpoint: "https://example.com/api/v1/users",
			},
			Vulnerability: normalization.Vulnerability{
				TemplateID: "cve-2024-9999",
				CWEID:      "CWE-79",
			},
			Title:    "XSS in Users API",
			Severity: "MEDIUM",
			Scanner: normalization.ScannerInfo{
				Name: "nuclei",
			},
			Evidence: []normalization.Evidence{
				{Type: "raw", ContentRedacted: "<script>alert(1)</script>"},
			},
		},
		{
			Target: normalization.Target{
				Asset:    "example.com",
				Endpoint: "https://example.com/api/v1/users",
			},
			Vulnerability: normalization.Vulnerability{
				TemplateID: "cve-2024-9999",
				CWEID:      "CWE-79",
			},
			Title:    "XSS in Users API",
			Severity: "MEDIUM",
			Scanner: normalization.ScannerInfo{
				Name: "owasp-zap",
			},
			Evidence: []normalization.Evidence{
				{Type: "raw", ContentRedacted: "<img src=x onerror=alert(2)>"},
			},
		},
	}

	ctx := context.Background()
	summary, err := svc.IngestBatch(ctx, tenantID, assessmentID, rawFindings, uuid.New())
	if err != nil {
		t.Fatalf("ingest batch failed: %v", err)
	}

	if summary.SameAssessmentDuplicates != 1 {
		t.Errorf("expected 1 same assessment duplicate, got %d", summary.SameAssessmentDuplicates)
	}

	if summary.NewFindings != 1 {
		t.Errorf("expected 1 new finding, got %d", summary.NewFindings)
	}

	if len(summary.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(summary.Observations))
	}

	// Verify both evidence payloads are retained
	if len(summary.Observations[0].EvidenceRefs) != 2 {
		t.Errorf("expected 2 evidence refs attached to observation, got %d", len(summary.Observations[0].EvidenceRefs))
	}
}
