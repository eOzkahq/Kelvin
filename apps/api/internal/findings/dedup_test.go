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

func TestCrossScannerCorrelationAndRepeatedScanDeduplication(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	asmt1ID := uuid.New()
	asmt2ID := uuid.New()
	job1ID := uuid.New()
	job2ID := uuid.New()
	corrID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			asmt1ID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: asmt1ID,
				JobID:        job1ID,
				Status:       "COMPLETED",
				TargetAsset:  "api.example.com",
			},
			asmt2ID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: asmt2ID,
				JobID:        job2ID,
				Status:       "COMPLETED",
				TargetAsset:  "api.example.com",
			},
		},
	}

	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	// Phase 1: In Assessment 1, Nmap and TLS Assessor discover overlapping TLS 1.0 issue
	nmapTLS := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com:443",
		},
		Vulnerability: normalization.Vulnerability{
			CWEID: "CWE-326",
		},
		Title:    "Deprecated TLS Protocol Version (TLS 1.0)",
		Severity: "MEDIUM",
		Scanner: normalization.ScannerInfo{
			Name: "nmap",
		},
		Evidence: []normalization.Evidence{
			{Type: "raw", ContentRedacted: "ssl-enum-ciphers: TLSv1.0 offered on port 443"},
		},
	}

	tlsAssessorTLS := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com:443",
		},
		Vulnerability: normalization.Vulnerability{
			CWEID: "CWE-326",
		},
		Title:    "Deprecated TLS Protocol Version (TLS 1.0)",
		Severity: "MEDIUM",
		Scanner: normalization.ScannerInfo{
			Name: "tls_assessor",
		},
		Evidence: []normalization.Evidence{
			{Type: "raw", ContentRedacted: "handshake: negotiated TLS 1.0 protocol"},
		},
	}

	sum1, err := svc.IngestBatch(ctx, tenantID, asmt1ID, []normalization.CanonicalFinding{nmapTLS, tlsAssessorTLS}, corrID)
	if err != nil {
		t.Fatalf("asmt 1 ingest failed: %v", err)
	}

	if sum1.NewFindings != 1 {
		t.Fatalf("expected 1 new finding in asmt 1, got %d", sum1.NewFindings)
	}
	if sum1.SameAssessmentDuplicates != 1 {
		t.Errorf("expected 1 same assessment duplicate in asmt 1, got %d", sum1.SameAssessmentDuplicates)
	}
	if len(repo.findings) != 1 {
		t.Fatalf("expected exactly 1 persistent finding, got %d", len(repo.findings))
	}

	var findingID uuid.UUID
	for id, f := range repo.findings {
		findingID = id
		if f.OccurrenceCount != 1 {
			t.Errorf("expected initial occurrence count 1, got %d", f.OccurrenceCount)
		}
		if f.Status != StatusOpen {
			t.Errorf("expected status OPEN, got %v", f.Status)
		}
	}

	// Phase 2: In Assessment 2, Nuclei re-detects the exact same TLS issue on repeated scan
	nucleiTLS := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com:443",
		},
		Vulnerability: normalization.Vulnerability{
			CWEID: "CWE-326",
		},
		Title:    "Deprecated TLS Protocol Version (TLS 1.0)",
		Severity: "MEDIUM",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
		Evidence: []normalization.Evidence{
			{Type: "raw", ContentRedacted: "nuclei: tls-version detected tls10"},
		},
	}

	sum2, err := svc.IngestBatch(ctx, tenantID, asmt2ID, []normalization.CanonicalFinding{nucleiTLS}, corrID)
	if err != nil {
		t.Fatalf("asmt 2 ingest failed: %v", err)
	}

	if sum2.NewFindings != 0 {
		t.Errorf("repeated scan must not create new finding, got %d", sum2.NewFindings)
	}
	if sum2.Redetected != 1 {
		t.Errorf("expected 1 redetected finding, got %d", sum2.Redetected)
	}
	if len(repo.findings) != 1 {
		t.Fatalf("must retain 1 unique persistent finding, got %d", len(repo.findings))
	}

	f := repo.findings[findingID]
	if f.OccurrenceCount != 2 {
		t.Errorf("expected occurrence count 2 after repeated scan, got %d", f.OccurrenceCount)
	}
	if len(repo.observations) != 2 {
		t.Errorf("expected 2 linked observations across scans, got %d", len(repo.observations))
	}

	// Phase 3: Cross-Scanner Correlation
	// Ingest Log4j finding with CVE-2021-44228 from scanner A, then from scanner B with matching CVE
	log4jFindingA := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com/api/v1/search",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "cve-2021-44228-nuclei",
			CVEIDs:     []string{"CVE-2021-44228"},
		},
		Title:    "Apache Log4j RCE (Nuclei)",
		Severity: "CRITICAL",
		Scanner: normalization.ScannerInfo{
			Name: "nuclei",
		},
	}

	log4jFindingB := normalization.CanonicalFinding{
		Target: normalization.Target{
			Asset:    "api.example.com",
			Endpoint: "https://api.example.com/api/v1/admin",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "cve-2021-44228-zap",
			CVEIDs:     []string{"CVE-2021-44228"},
		},
		Title:    "Apache Log4j JNDI Injection (ZAP)",
		Severity: "CRITICAL",
		Scanner: normalization.ScannerInfo{
			Name: "zap",
		},
	}

	sum3, err := svc.IngestBatch(ctx, tenantID, asmt2ID, []normalization.CanonicalFinding{log4jFindingA, log4jFindingB}, corrID)
	if err != nil {
		t.Fatalf("log4j batch ingest failed: %v", err)
	}

	if sum3.NewFindings != 2 {
		t.Fatalf("expected 2 new distinct location findings, got %d", sum3.NewFindings)
	}

	// Verify correlation group was created by Rule 1 (Common CVE on same host)
	if len(repo.groups) == 0 {
		t.Errorf("expected correlation group to be created for shared CVE-2021-44228")
	} else {
		for _, g := range repo.groups {
			if g.CorrelationType != CorrelationCommonID {
				t.Errorf("expected correlation type COMMON_IDENTIFIER, got %v", g.CorrelationType)
			}
			members := repo.groupMembers[g.ID]
			if len(members) != 2 {
				t.Errorf("expected 2 members in correlation group, got %d", len(members))
			}
		}
	}
}
