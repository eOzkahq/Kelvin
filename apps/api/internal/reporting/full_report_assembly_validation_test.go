package reporting_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/reporting"
)

// mockReportingDataSource implements reporting.AssessmentDataSource,
// reporting.FindingDataSource, and reporting.RemediationDataSource.
type mockReportingDataSource struct {
	assessment   *reporting.AssessmentRecord
	findings     []reporting.ReportFindingItem
	remediations map[uuid.UUID][]reporting.ReportRemediationItem
}

func (m *mockReportingDataSource) GetAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*reporting.AssessmentRecord, error) {
	if m.assessment == nil || m.assessment.ID != assessmentID {
		return nil, reporting.ErrAssessmentNotFound
	}
	if m.assessment.TenantID != tenantID {
		return nil, reporting.ErrTenantMismatch
	}
	return m.assessment, nil
}

func (m *mockReportingDataSource) GetAssessmentFindings(ctx context.Context, tenantID, assessmentID uuid.UUID) ([]reporting.ReportFindingItem, error) {
	if m.assessment == nil || m.assessment.TenantID != tenantID {
		return nil, reporting.ErrTenantMismatch
	}
	return m.findings, nil
}

func (m *mockReportingDataSource) GetRemediationGuidance(ctx context.Context, tenantID, findingID uuid.UUID) ([]reporting.ReportRemediationItem, error) {
	return m.remediations[findingID], nil
}

// TestFullIngestion_AssessmentReportAssemblyAndContractValidation validates that the
// customer-facing assessment report document is accurately assembled from ingested findings,
// produces exact matching severity metrics, and fulfills the full ReportV1 contract.
func TestFullIngestion_AssessmentReportAssemblyAndContractValidation(t *testing.T) {
	ctx := context.Background()

	tenantUUID := uuid.New()
	asmtUUID := uuid.New()

	finding1 := reporting.ReportFindingItem{
		FindingID:   uuid.New(),
		Fingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Title:       "Critical RCE in Log4j",
		Severity:    "CRITICAL",
		Status:      "OPEN",
		Endpoint:    "https://target.corp/api/login",
		CVEIDs:      []string{"CVE-2021-44228"},
		SanitizedEvidence: []reporting.ReportEvidenceExcerpt{
			{
				EvidenceID:       uuid.New(),
				EvidenceType:     "LOG",
				SanitizedContent: "sanitized evidence payload",
				RedactionApplied: true,
			},
		},
	}

	finding2 := reporting.ReportFindingItem{
		FindingID:   uuid.New(),
		Fingerprint: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Title:       "High SQL Injection",
		Severity:    "HIGH",
		Status:      "OPEN",
		Endpoint:    "https://target.corp/search",
	}

	finding3 := reporting.ReportFindingItem{
		FindingID:   uuid.New(),
		Fingerprint: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Title:       "Medium Anti-Clickjacking Missing",
		Severity:    "MEDIUM",
		Status:      "OPEN",
		Endpoint:    "https://target.corp/",
	}

	asmtRecord := &reporting.AssessmentRecord{
		ID:          asmtUUID,
		TenantID:    tenantUUID,
		ProjectID:   uuid.New(),
		Targets:     []string{"https://target.corp"},
		Scanners:    []string{"nuclei", "zap"},
		Profile:     "standard",
		Status:      "COMPLETED",
		IsPartial:   false,
		StartedAt:   time.Now().UTC().Add(-10 * time.Minute),
		CompletedAt: time.Now().UTC(),
	}

	ds := &mockReportingDataSource{
		assessment: asmtRecord,
		findings:   []reporting.ReportFindingItem{finding1, finding2, finding3},
		remediations: map[uuid.UUID][]reporting.ReportRemediationItem{
			finding1.FindingID: {
				{
					FindingID:         finding1.FindingID,
					Title:             "Upgrade Log4j to 2.17.1",
					RecommendedAction: "Upgrade the vulnerable Log4j library to mitigate RCE",
					State:             "OPEN",
				},
			},
		},
	}

	snapshotRepo := reporting.NewMemorySnapshotRepository()
	assemblyService := reporting.NewReportAssemblyService(ds, ds, ds, snapshotRepo)

	// Assemble Report
	report, err := assemblyService.AssembleReport(ctx, tenantUUID, asmtUUID, "Kelvin Security Assessment Report", "kelvin-report-v1")
	if err != nil {
		t.Fatalf("AssembleReport failed: %v", err)
	}

	// 1. Validate Report contract
	if err := report.Validate(); err != nil {
		t.Fatalf("ReportV1.Validate failed: %v", err)
	}

	// 2. Validate Summary severity counts match ingested findings
	if report.Summary.TotalFindings != 3 {
		t.Errorf("expected 3 total findings in report summary, got %d", report.Summary.TotalFindings)
	}
	if report.Summary.CriticalCount != 1 {
		t.Errorf("expected 1 critical finding, got %d", report.Summary.CriticalCount)
	}
	if report.Summary.HighCount != 1 {
		t.Errorf("expected 1 high finding, got %d", report.Summary.HighCount)
	}
	if report.Summary.MediumCount != 1 {
		t.Errorf("expected 1 medium finding, got %d", report.Summary.MediumCount)
	}
	if report.Summary.PostureBand != "CRITICAL" {
		t.Errorf("expected PostureBand CRITICAL due to critical finding, got %s", report.Summary.PostureBand)
	}

	// 3. Verify Remediation guidance
	if len(report.RemediationGuidance) != 1 {
		t.Errorf("expected 1 remediation item, got %d", len(report.RemediationGuidance))
	}

	// 4. Serialize and Parse Report JSON
	jsonBytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("report.ToJSON failed: %v", err)
	}
	if len(jsonBytes) == 0 {
		t.Fatal("expected non-empty report JSON bytes")
	}

	parsedReport, err := reporting.ParseReportV1(jsonBytes)
	if err != nil {
		t.Fatalf("ParseReportV1 failed: %v", err)
	}
	if parsedReport.ReportID != report.ReportID {
		t.Errorf("parsed ReportID mismatch: got %s, expected %s", parsedReport.ReportID, report.ReportID)
	}
	if len(parsedReport.Findings) != 3 {
		t.Errorf("expected 3 findings in parsed report, got %d", len(parsedReport.Findings))
	}
}

// TestFullIngestion_TenantIsolation verifies that assessment findings and report snapshots
// for Tenant A cannot be accessed or assembled by Tenant B.
func TestFullIngestion_TenantIsolation(t *testing.T) {
	ctx := context.Background()

	tenantA := uuid.New()
	tenantB := uuid.New()
	asmtID := uuid.New()

	asmtRecord := &reporting.AssessmentRecord{
		ID:        asmtID,
		TenantID:  tenantA,
		Targets:   []string{"https://corp-a.test"},
		Status:    "COMPLETED",
		StartedAt: time.Now().UTC().Add(-time.Hour),
	}

	ds := &mockReportingDataSource{
		assessment: asmtRecord,
	}

	snapshotRepo := reporting.NewMemorySnapshotRepository()
	assemblyService := reporting.NewReportAssemblyService(ds, ds, nil, snapshotRepo)

	// Tenant B tries to assemble Tenant A's assessment report -> must fail with ErrTenantMismatch
	_, err := assemblyService.AssembleReport(ctx, tenantB, asmtID, "Unauthorized Report", "v1")
	if err == nil {
		t.Fatal("security violation: Tenant B assembled Tenant A's assessment report")
	}
	if !strings.Contains(err.Error(), "tenant boundary violation") && err != reporting.ErrTenantMismatch {
		t.Errorf("expected tenant boundary violation error, got: %v", err)
	}
}
