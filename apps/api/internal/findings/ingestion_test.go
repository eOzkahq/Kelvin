package findings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

type mockAssessmentValidator struct {
	assessments map[uuid.UUID]*AssessmentContext
}

func (m *mockAssessmentValidator) ValidateAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*AssessmentContext, error) {
	asmt, exists := m.assessments[assessmentID]
	if !exists {
		return nil, ErrAssessmentNotFound
	}
	if asmt.TenantID != tenantID {
		return nil, ErrAssessmentTenantMismatch
	}
	return asmt, nil
}

type mockFindingRepo struct {
	findings     map[uuid.UUID]*PersistentFinding
	observations map[uuid.UUID]*FindingObservation
	events       map[uuid.UUID]*FindingEvent
}

func newMockFindingRepo() *mockFindingRepo {
	return &mockFindingRepo{
		findings:     make(map[uuid.UUID]*PersistentFinding),
		observations: make(map[uuid.UUID]*FindingObservation),
		events:       make(map[uuid.UUID]*FindingEvent),
	}
}

func (m *mockFindingRepo) GetFindingsByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]*PersistentFinding, error) {
	var res []*PersistentFinding
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.ProjectID == projectID {
			res = append(res, f)
		}
	}
	return res, nil
}

func (m *mockFindingRepo) GetFindingByID(ctx context.Context, tenantID, findingID uuid.UUID) (*PersistentFinding, error) {
	f, exists := m.findings[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, ErrFindingNotFound
	}
	return f, nil
}

func (m *mockFindingRepo) GetObservationsByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*FindingObservation, error) {
	var res []*FindingObservation
	for _, obs := range m.observations {
		if obs.TenantID == tenantID && obs.FindingID == findingID {
			res = append(res, obs)
		}
	}
	return res, nil
}

func (m *mockFindingRepo) ObservationExists(ctx context.Context, tenantID, assessmentID, findingID uuid.UUID) (bool, error) {
	for _, obs := range m.observations {
		if obs.TenantID == tenantID && obs.AssessmentID == assessmentID && obs.FindingID == findingID {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockFindingRepo) SaveFinding(ctx context.Context, f *PersistentFinding) error {
	m.findings[f.ID] = f
	return nil
}

func (m *mockFindingRepo) SaveObservation(ctx context.Context, obs *FindingObservation) error {
	m.observations[obs.ID] = obs
	return nil
}

func (m *mockFindingRepo) SaveEvent(ctx context.Context, ev *FindingEvent) error {
	m.events[ev.ID] = ev
	return nil
}

type mockEventPublisher struct {
	published []IngestionSummary
}

func (m *mockEventPublisher) PublishFindingsIngested(ctx context.Context, tenantID, assessmentID uuid.UUID, summary IngestionSummary) error {
	m.published = append(m.published, summary)
	return nil
}

func TestIngestBatchSuccessful(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	assessmentID := uuid.New()
	jobID := uuid.New()
	corrID := uuid.New()

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
	repo := newMockFindingRepo()
	publisher := &mockEventPublisher{}

	svc := NewIngestionService(validator, repo, publisher)

	canonicalFindings := []normalization.CanonicalFinding{
		{
			SchemaVersion: "1.0.0",
			Title:         "SQL Injection in /api/v1/search",
			Severity:      "HIGH",
			Confidence:    0.95,
			Target: normalization.Target{
				Asset:    "example.com",
				Endpoint: "https://example.com/api/v1/search",
				Method:   "GET",
			},
			Vulnerability: normalization.Vulnerability{
				TemplateID: "sqli-query",
				CWEID:      "CWE-89",
				CVEIDs:     []string{"CVE-2023-9999"},
				CVSS: &normalization.CVSSInfo{
					Version: "3.1",
					Score:   8.8,
				},
			},
			Scanner: normalization.ScannerInfo{
				Name:           "nuclei",
				AdapterVersion: "v1.2.0",
				EngineVersion:  "v3.1.0",
				RunID:          "run-1234",
			},
			Evidence: []normalization.Evidence{
				{
					ID:             "ev-001",
					Type:           "http_request_response",
					ChecksumSHA256: "aabbcc112233",
				},
			},
			DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
		},
	}

	summary, err := svc.IngestBatch(ctx, tenantID, assessmentID, canonicalFindings, corrID)
	if err != nil {
		t.Fatalf("IngestBatch failed: %v", err)
	}

	if summary.TotalProcessed != 1 {
		t.Errorf("expected 1 processed, got %d", summary.TotalProcessed)
	}
	if summary.NewFindings != 1 {
		t.Errorf("expected 1 new finding, got %d", summary.NewFindings)
	}
	if summary.Redetected != 0 {
		t.Errorf("expected 0 redetected, got %d", summary.Redetected)
	}
	if len(repo.findings) != 1 {
		t.Errorf("expected 1 finding stored, got %d", len(repo.findings))
	}
	if len(repo.observations) != 1 {
		t.Errorf("expected 1 observation stored, got %d", len(repo.observations))
	}
	if len(publisher.published) != 1 {
		t.Errorf("expected 1 event published, got %d", len(publisher.published))
	}

	// Verify provenance preservation
	for _, obs := range repo.observations {
		if obs.ScannerID != "nuclei" {
			t.Errorf("expected scanner ID nuclei, got %s", obs.ScannerID)
		}
		if obs.RawMetadata["engine_version"] != "v3.1.0" {
			t.Errorf("engine version not preserved in metadata: %v", obs.RawMetadata)
		}
	}
}

func TestIngestBatchRedetectionInSubsequentScan(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	asmt1ID := uuid.New()
	asmt2ID := uuid.New()
	job1 := uuid.New()
	job2 := uuid.New()
	corrID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			asmt1ID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: asmt1ID,
				JobID:        job1,
				Status:       "COMPLETED",
			},
			asmt2ID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: asmt2ID,
				JobID:        job2,
				Status:       "COMPLETED",
			},
		},
	}
	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	findingPayload := normalization.CanonicalFinding{
		Title:      "Cross-Site Scripting (Reflected)",
		Severity:   "MEDIUM",
		Confidence: 0.8,
		Target: normalization.Target{
			Asset:    "app.example.com",
			Endpoint: "https://app.example.com/profile",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "xss-reflected",
			CWEID:      "CWE-79",
		},
		Scanner: normalization.ScannerInfo{
			Name: "zap",
		},
	}

	// 1. First Scan
	sum1, err := svc.IngestBatch(ctx, tenantID, asmt1ID, []normalization.CanonicalFinding{findingPayload}, corrID)
	if err != nil {
		t.Fatalf("first scan ingestion failed: %v", err)
	}
	if sum1.NewFindings != 1 {
		t.Fatalf("expected 1 new finding, got %d", sum1.NewFindings)
	}

	// 2. Second Scan with same target and template
	findingPayload2 := findingPayload
	findingPayload2.Scanner.Name = "nuclei" // Different scanner observing same finding
	sum2, err := svc.IngestBatch(ctx, tenantID, asmt2ID, []normalization.CanonicalFinding{findingPayload2}, corrID)
	if err != nil {
		t.Fatalf("second scan ingestion failed: %v", err)
	}

	if sum2.NewFindings != 0 {
		t.Errorf("expected 0 new findings, got %d", sum2.NewFindings)
	}
	if sum2.Redetected != 1 {
		t.Errorf("expected 1 redetected finding, got %d", sum2.Redetected)
	}
	if len(repo.findings) != 1 {
		t.Errorf("must not create duplicate persistent findings, got %d", len(repo.findings))
	}
	if len(repo.observations) != 2 {
		t.Errorf("must retain immutable observation per scan, got %d", len(repo.observations))
	}

	// Occurrence count must be 2
	for _, f := range repo.findings {
		if f.OccurrenceCount != 2 {
			t.Errorf("expected occurrence count 2, got %d", f.OccurrenceCount)
		}
	}
}

func TestIngestBatchRejectsInvalidOrInaccessibleAssessments(t *testing.T) {
	ctx := context.Background()
	tenantA := uuid.New()
	tenantB := uuid.New()
	assessmentID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			assessmentID: {
				TenantID:     tenantA,
				AssessmentID: assessmentID,
				Status:       "COMPLETED",
			},
		},
	}
	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	// Inaccessible assessment (Tenant B trying to ingest into Tenant A's assessment)
	_, err := svc.IngestBatch(ctx, tenantB, assessmentID, nil, uuid.New())
	if err != ErrAssessmentTenantMismatch {
		t.Errorf("expected ErrAssessmentTenantMismatch, got %v", err)
	}

	// Non-existent assessment
	_, err = svc.IngestBatch(ctx, tenantA, uuid.New(), nil, uuid.New())
	if err != ErrAssessmentNotFound {
		t.Errorf("expected ErrAssessmentNotFound, got %v", err)
	}
}

func TestIngestBatchHandlesPartialAssessments(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	assessmentID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			assessmentID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: assessmentID,
				Status:       "COMPLETED_WITH_WARNINGS",
			},
		},
	}
	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	findings := []normalization.CanonicalFinding{
		{
			Title:      "TLS Weak Cipher",
			Severity:   "LOW",
			Confidence: 0.9,
			Target: normalization.Target{
				Asset: "secure.example.com",
			},
			Vulnerability: normalization.Vulnerability{
				TemplateID: "tls-weak-cipher",
			},
			Scanner: normalization.ScannerInfo{
				Name: "tls-analyzer",
			},
		},
	}

	sum, err := svc.IngestBatch(ctx, tenantID, assessmentID, findings, uuid.New())
	if err != nil {
		t.Fatalf("partial assessment ingestion failed: %v", err)
	}

	if sum.TotalProcessed != 1 {
		t.Errorf("expected 1 processed, got %d", sum.TotalProcessed)
	}

	for _, obs := range repo.observations {
		if obs.RawMetadata["partial_scan"] != true {
			t.Errorf("expected partial_scan flag in observation metadata: %v", obs.RawMetadata)
		}
	}
}

func TestIngestBatchRejectsCancelledOrFailedAssessments(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	asmtCancelled := uuid.New()
	asmtFailed := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			asmtCancelled: {
				TenantID:     tenantID,
				AssessmentID: asmtCancelled,
				Status:       "CANCELLED",
			},
			asmtFailed: {
				TenantID:     tenantID,
				AssessmentID: asmtFailed,
				Status:       "FAILED",
			},
		},
	}
	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	_, err := svc.IngestBatch(ctx, tenantID, asmtCancelled, nil, uuid.New())
	if err != ErrAssessmentCancelled {
		t.Errorf("expected ErrAssessmentCancelled, got %v", err)
	}

	_, err = svc.IngestBatch(ctx, tenantID, asmtFailed, nil, uuid.New())
	if err != ErrAssessmentFailed {
		t.Errorf("expected ErrAssessmentFailed, got %v", err)
	}
}

func TestIngestBatchIdempotencyOnRepeatedDelivery(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	assessmentID := uuid.New()
	jobID := uuid.New()
	corrID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			assessmentID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: assessmentID,
				JobID:        jobID,
				Status:       "COMPLETED",
			},
		},
	}
	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	canonicalFindings := []normalization.CanonicalFinding{
		{
			Title:      "Cross-Site Scripting",
			Severity:   "HIGH",
			Confidence: 0.9,
			Target: normalization.Target{
				Asset:    "app.example.com",
				Endpoint: "https://app.example.com/comment",
			},
			Vulnerability: normalization.Vulnerability{
				TemplateID: "xss-comment",
				CWEID:      "CWE-79",
			},
			Scanner: normalization.ScannerInfo{
				Name: "nuclei",
			},
		},
	}

	// First delivery
	sum1, err := svc.IngestBatch(ctx, tenantID, assessmentID, canonicalFindings, corrID)
	if err != nil {
		t.Fatalf("first delivery failed: %v", err)
	}
	if sum1.NewFindings != 1 || sum1.Replayed != 0 {
		t.Errorf("expected 1 new finding, 0 replayed; got %d new, %d replayed", sum1.NewFindings, sum1.Replayed)
	}
	if len(repo.observations) != 1 {
		t.Errorf("expected 1 observation, got %d", len(repo.observations))
	}

	// Repeated delivery (queue retry / network redelivery of same assessment)
	sum2, err := svc.IngestBatch(ctx, tenantID, assessmentID, canonicalFindings, corrID)
	if err != nil {
		t.Fatalf("second delivery failed: %v", err)
	}
	if sum2.NewFindings != 0 {
		t.Errorf("expected 0 new findings on redelivery, got %d", sum2.NewFindings)
	}
	if sum2.Redetected != 0 {
		t.Errorf("expected 0 redetected on redelivery of same assessment, got %d", sum2.Redetected)
	}
	if sum2.Replayed != 1 {
		t.Errorf("expected 1 replayed finding, got %d", sum2.Replayed)
	}
	if len(repo.observations) != 1 {
		t.Errorf("must NOT duplicate observations on redelivery, got %d", len(repo.observations))
	}

	// Finding occurrence count must remain 1
	for _, f := range repo.findings {
		if f.OccurrenceCount != 1 {
			t.Errorf("expected occurrence count 1 after replay, got %d", f.OccurrenceCount)
		}
	}
}

func TestIngestBatchPreservesAnalystStatusOnRetry(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	projectID := uuid.New()
	assessmentID := uuid.New()
	jobID := uuid.New()
	corrID := uuid.New()

	validator := &mockAssessmentValidator{
		assessments: map[uuid.UUID]*AssessmentContext{
			assessmentID: {
				TenantID:     tenantID,
				ProjectID:    projectID,
				AssessmentID: assessmentID,
				JobID:        jobID,
				Status:       "COMPLETED",
			},
		},
	}
	repo := newMockFindingRepo()
	svc := NewIngestionService(validator, repo, nil)

	findingPayload := normalization.CanonicalFinding{
		Title:      "Informational Header Disclosure",
		Severity:   "LOW",
		Confidence: 0.9,
		Target: normalization.Target{
			Asset: "api.example.com",
		},
		Vulnerability: normalization.Vulnerability{
			TemplateID: "server-header",
		},
		Scanner: normalization.ScannerInfo{
			Name: "header-checker",
		},
	}

	// 1. Ingest finding
	_, err := svc.IngestBatch(ctx, tenantID, assessmentID, []normalization.CanonicalFinding{findingPayload}, corrID)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Analyst marks as FALSE_POSITIVE
	for _, f := range repo.findings {
		f.Status = StatusFalsePositive
	}

	// 3. Retry of the same assessment payload occurs
	sum, err := svc.IngestBatch(ctx, tenantID, assessmentID, []normalization.CanonicalFinding{findingPayload}, corrID)
	if err != nil {
		t.Fatal(err)
	}

	if sum.Replayed != 1 {
		t.Errorf("expected replay count 1, got %d", sum.Replayed)
	}

	// 4. Verify status is still FALSE_POSITIVE
	for _, f := range repo.findings {
		if f.Status != StatusFalsePositive {
			t.Errorf("analyst status overwritten on retry! Expected FALSE_POSITIVE, got %s", f.Status)
		}
	}
}

