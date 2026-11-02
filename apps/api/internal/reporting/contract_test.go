package reporting

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleValidReport() *ReportV1 {
	cvss := 9.8
	riskScore := 92.5
	now := time.Now().UTC()

	return &ReportV1{
		SchemaVersion:   CurrentSchemaVersion,
		ReportID:        uuid.New(),
		AssessmentID:    uuid.New(),
		TenantID:        uuid.New(),
		Title:           "Quarterly External Perimeter Security Assessment",
		GeneratedAt:     now,
		TemplateVersion: DefaultTemplateID,
		Summary: ReportSummary{
			OverallRiskScore:   78.4,
			PostureBand:        "HIGH",
			TotalFindings:      3,
			CriticalCount:      1,
			HighCount:          1,
			MediumCount:        1,
			LowCount:           0,
			InfoCount:          0,
			ExecutiveNarrative: "External assessment revealed 1 critical vulnerability requiring immediate remediation.",
		},
		Scope: ReportScope{
			Targets:  []string{"https://api.example.com", "https://app.example.com"},
			Scanners: []string{"nuclei", "zap", "tls"},
			Profile:  "full-external-audit",
		},
		ExecutionStatus: ReportExecutionStatus{
			Status:      "COMPLETED",
			IsPartial:   false,
			StartedAt:   now.Add(-2 * time.Hour),
			CompletedAt: now,
		},
		FindingsSummary: ReportFindingsSummary{
			SeverityBreakdown: map[string]int{"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
			PriorityBreakdown: map[string]int{"P1": 1, "P2": 1, "P3": 1},
		},
		Findings: []ReportFindingItem{
			{
				FindingID:   uuid.New(),
				Fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Title:       "Remote Code Execution via Spring4Shell",
				Severity:    "CRITICAL",
				Status:      "CONFIRMED",
				CVSSScore:   &cvss,
				CWEID:       "CWE-94",
				CVEIDs:      []string{"CVE-2022-22965"},
				Endpoint:    "https://api.example.com/helloworld",
				RiskScore:   &riskScore,
				RiskBand:    "CRITICAL",
				SanitizedEvidence: []ReportEvidenceExcerpt{
					{
						EvidenceID:       uuid.New(),
						EvidenceType:     "HTTP_EXCERPT",
						SanitizedContent: "POST /helloworld HTTP/1.1\nHost: api.example.com\nAuthorization: [REDACTED_AUTHORIZATION_TOKEN]",
						RedactionApplied: true,
					},
				},
			},
		},
		RemediationGuidance: []ReportRemediationItem{
			{
				FindingID:         uuid.New(),
				Title:             "Upgrade Spring Framework",
				RecommendedAction: "Upgrade spring-beans to version 5.3.18 or higher",
				State:             "OPEN",
			},
		},
		Provenance: ReportProvenance{
			EngineVersion: "kelvin-engine-v1.4.0",
			TemplateID:    DefaultTemplateID,
			AuditHash:     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			Disclaimer:    "This security assessment represents security posture at time of testing.",
		},
	}
}

func TestReportV1_SerializationAndValidation(t *testing.T) {
	t.Run("valid report serialization round-trip", func(t *testing.T) {
		report := sampleValidReport()
		data, err := report.ToJSON()
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		parsed, err := ParseReportV1(data)
		require.NoError(t, err)
		assert.Equal(t, report.ReportID, parsed.ReportID)
		assert.Equal(t, report.Title, parsed.Title)
		assert.Equal(t, report.Summary.OverallRiskScore, parsed.Summary.OverallRiskScore)
		assert.Len(t, parsed.Findings, 1)
		assert.True(t, parsed.Findings[0].SanitizedEvidence[0].RedactionApplied)
	})

	t.Run("missing required IDs", func(t *testing.T) {
		report := sampleValidReport()
		report.ReportID = uuid.Nil
		assert.ErrorIs(t, report.Validate(), ErrInvalidReportID)

		report = sampleValidReport()
		report.AssessmentID = uuid.Nil
		assert.ErrorIs(t, report.Validate(), ErrInvalidAssessmentID)

		report = sampleValidReport()
		report.TenantID = uuid.Nil
		assert.ErrorIs(t, report.Validate(), ErrInvalidTenantID)
	})

	t.Run("missing title or template", func(t *testing.T) {
		report := sampleValidReport()
		report.Title = ""
		assert.ErrorIs(t, report.Validate(), ErrMissingReportTitle)

		report = sampleValidReport()
		report.TemplateVersion = ""
		assert.ErrorIs(t, report.Validate(), ErrMissingTemplateVersion)
	})

	t.Run("partial assessment without disclosure", func(t *testing.T) {
		report := sampleValidReport()
		report.ExecutionStatus.IsPartial = true
		report.ExecutionStatus.PartialDisclosures = nil
		assert.ErrorIs(t, report.Validate(), ErrPartialWithoutNotice)

		report.ExecutionStatus.PartialDisclosures = []string{"ZAP crawler timed out after 30 minutes"}
		assert.NoError(t, report.Validate())
	})
}
