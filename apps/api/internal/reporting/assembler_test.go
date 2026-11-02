package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAssessmentSource struct {
	assessments map[uuid.UUID]*AssessmentRecord
}

func (m *mockAssessmentSource) GetAssessment(_ context.Context, tenantID, assessmentID uuid.UUID) (*AssessmentRecord, error) {
	a, exists := m.assessments[assessmentID]
	if !exists {
		return nil, ErrAssessmentNotFound
	}
	if a.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return a, nil
}

type mockFindingSource struct {
	findings map[uuid.UUID][]ReportFindingItem
}

func (m *mockFindingSource) GetAssessmentFindings(_ context.Context, _, assessmentID uuid.UUID) ([]ReportFindingItem, error) {
	return m.findings[assessmentID], nil
}

type mockRemediationSource struct {
	remediations map[uuid.UUID][]ReportRemediationItem
}

func (m *mockRemediationSource) GetRemediationGuidance(_ context.Context, _, findingID uuid.UUID) ([]ReportRemediationItem, error) {
	return m.remediations[findingID], nil
}

func TestReportAssemblyService(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	assessmentID := uuid.New()
	findingID := uuid.New()

	now := time.Now().UTC()
	assessment := &AssessmentRecord{
		ID:                 assessmentID,
		TenantID:           tenantID,
		ProjectID:          uuid.New(),
		Targets:            []string{"https://api.kelvin.internal"},
		Scanners:           []string{"nuclei", "zap"},
		Profile:            "standard-audit",
		Status:             "COMPLETED",
		IsPartial:          false,
		StartedAt:          now.Add(-1 * time.Hour),
		CompletedAt:        now,
		PartialDisclosures: nil,
	}

	cvss := 8.5
	riskScore := 88.0
	findings := []ReportFindingItem{
		{
			FindingID:   findingID,
			Fingerprint: "fp-audit-001",
			Title:       "SQL Injection in Search API",
			Severity:    "HIGH",
			Status:      "CONFIRMED",
			CVSSScore:   &cvss,
			CWEID:       "CWE-89",
			CVEIDs:      []string{"CVE-2023-9999"},
			Endpoint:    "https://api.kelvin.internal/search?q=",
			RiskScore:   &riskScore,
			RiskBand:    "P1",
			SanitizedEvidence: []ReportEvidenceExcerpt{
				{
					EvidenceID:       uuid.New(),
					EvidenceType:     "HTTP_EXCERPT",
					SanitizedContent: "SELECT * FROM users WHERE id = '1' [REDACTED_SQL_ERROR]",
					RedactionApplied: false, // Assembler will enforce true
				},
			},
		},
	}

	remediations := []ReportRemediationItem{
		{
			FindingID:         findingID,
			Title:             "Use Parameterized Queries",
			RecommendedAction: "Switch all raw SQL queries to prepared statements",
			State:             "IN_PROGRESS",
		},
	}

	asSource := &mockAssessmentSource{assessments: map[uuid.UUID]*AssessmentRecord{assessmentID: assessment}}
	fSource := &mockFindingSource{findings: map[uuid.UUID][]ReportFindingItem{assessmentID: findings}}
	rSource := &mockRemediationSource{remediations: map[uuid.UUID][]ReportRemediationItem{findingID: remediations}}
	snapshotRepo := NewMemorySnapshotRepository()

	service := NewReportAssemblyService(asSource, fSource, rSource, snapshotRepo)

	t.Run("successful report assembly and snapshot storage", func(t *testing.T) {
		report, err := service.AssembleReport(ctx, tenantID, assessmentID, "Security Assessment Report Q4", DefaultTemplateID)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, report.ReportID)
		assert.Equal(t, assessmentID, report.AssessmentID)
		assert.Equal(t, tenantID, report.TenantID)
		assert.Equal(t, "Security Assessment Report Q4", report.Title)
		assert.Equal(t, "HIGH", report.Summary.PostureBand)
		assert.Equal(t, 1, report.Summary.HighCount)
		assert.Equal(t, 88.0, report.Summary.OverallRiskScore)
		assert.NotEmpty(t, report.Provenance.AuditHash)

		// Verify evidence is sanitized
		require.Len(t, report.Findings, 1)
		assert.True(t, report.Findings[0].SanitizedEvidence[0].RedactionApplied)

		// Verify remediation guidance included
		require.Len(t, report.RemediationGuidance, 1)
		assert.Equal(t, "Use Parameterized Queries", report.RemediationGuidance[0].Title)

		// Verify snapshot retrieved from repo
		snapshot, err := snapshotRepo.GetSnapshot(ctx, tenantID, report.ReportID)
		require.NoError(t, err)
		assert.Equal(t, report.ReportID, snapshot.ReportID)
		assert.Equal(t, "Security Assessment Report Q4", snapshot.Title)
		assert.Equal(t, report.Summary.OverallRiskScore, snapshot.SnapshotData.Summary.OverallRiskScore)
	})

	t.Run("partial assessment disclosure included", func(t *testing.T) {
		partialAssessmentID := uuid.New()
		partialAssessment := &AssessmentRecord{
			ID:                 partialAssessmentID,
			TenantID:           tenantID,
			Targets:            []string{"https://api.kelvin.internal"},
			Scanners:           []string{"nuclei"},
			Profile:            "standard-audit",
			Status:             "PARTIAL",
			IsPartial:          true,
			StartedAt:          now.Add(-30 * time.Minute),
			CompletedAt:        now,
			PartialDisclosures: []string{"ZAP scan skipped due to network timeout"},
		}
		asSource.assessments[partialAssessmentID] = partialAssessment
		fSource.findings[partialAssessmentID] = []ReportFindingItem{}

		report, err := service.AssembleReport(ctx, tenantID, partialAssessmentID, "Partial Audit Report", DefaultTemplateID)
		require.NoError(t, err)
		assert.True(t, report.ExecutionStatus.IsPartial)
		assert.Contains(t, report.ExecutionStatus.PartialDisclosures[0], "ZAP scan skipped")
	})

	t.Run("tenant isolation enforcement", func(t *testing.T) {
		otherTenant := uuid.New()
		_, err := service.AssembleReport(ctx, otherTenant, assessmentID, "Cross Tenant Report", DefaultTemplateID)
		assert.ErrorIs(t, err, ErrTenantMismatch)
	})

	t.Run("snapshot repository tenant isolation", func(t *testing.T) {
		report, err := service.AssembleReport(ctx, tenantID, assessmentID, "Tenant Check", DefaultTemplateID)
		require.NoError(t, err)

		otherTenant := uuid.New()
		_, err = snapshotRepo.GetSnapshot(ctx, otherTenant, report.ReportID)
		assert.ErrorIs(t, err, ErrTenantMismatch)
	})
}
