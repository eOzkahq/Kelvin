package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	CurrentSchemaVersion = "1.0"
	DefaultTemplateID    = "kelvin-assessment-report-v1"
)

var (
	ErrInvalidReportID        = errors.New("reporting: invalid or missing report ID")
	ErrInvalidAssessmentID    = errors.New("reporting: invalid or missing assessment ID")
	ErrInvalidTenantID        = errors.New("reporting: invalid or missing tenant ID")
	ErrMissingReportTitle     = errors.New("reporting: report title is required")
	ErrPartialWithoutNotice   = errors.New("reporting: partial assessments must disclose limitations")
	ErrMissingTemplateVersion = errors.New("reporting: template version is required")
)

// ReportV1 defines the customer-facing assessment report document contract (report.v1.json).
type ReportV1 struct {
	SchemaVersion       string                 `json:"schema_version"`
	ReportID            uuid.UUID              `json:"report_id"`
	AssessmentID        uuid.UUID              `json:"assessment_id"`
	TenantID            uuid.UUID              `json:"tenant_id"`
	Title               string                 `json:"title"`
	GeneratedAt         time.Time              `json:"generated_at"`
	TemplateVersion     string                 `json:"template_version"`
	Summary             ReportSummary          `json:"summary"`
	Scope               ReportScope            `json:"scope"`
	ExecutionStatus     ReportExecutionStatus  `json:"execution_status"`
	FindingsSummary     ReportFindingsSummary  `json:"findings_summary"`
	Findings            []ReportFindingItem    `json:"findings"`
	RemediationGuidance []ReportRemediationItem `json:"remediation_guidance"`
	Provenance          ReportProvenance       `json:"provenance"`
}

// ReportSummary encapsulates the executive overview and posture score.
type ReportSummary struct {
	OverallRiskScore   float64 `json:"overall_risk_score"`
	PostureBand        string  `json:"posture_band"` // "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
	TotalFindings      int     `json:"total_findings"`
	CriticalCount      int     `json:"critical_count"`
	HighCount          int     `json:"high_count"`
	MediumCount        int     `json:"medium_count"`
	LowCount           int     `json:"low_count"`
	InfoCount          int     `json:"info_count"`
	ExecutiveNarrative string  `json:"executive_narrative,omitempty"`
}

// ReportScope defines the target boundaries and scanners utilized.
type ReportScope struct {
	Targets  []string `json:"targets"`
	Scanners []string `json:"scanners"`
	Profile  string   `json:"profile"`
}

// ReportExecutionStatus documents run status and partial assessment disclosures.
type ReportExecutionStatus struct {
	Status             string    `json:"status"` // "COMPLETED", "PARTIAL", "FAILED"
	IsPartial          bool      `json:"is_partial"`
	StartedAt          time.Time `json:"started_at"`
	CompletedAt        time.Time `json:"completed_at"`
	PartialDisclosures []string  `json:"partial_disclosures,omitempty"`
	Limitations        []string  `json:"limitations,omitempty"`
}

// ReportFindingsSummary provides categorical breakdowns.
type ReportFindingsSummary struct {
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	PriorityBreakdown map[string]int `json:"priority_breakdown"`
}

// ReportFindingItem represents an individual vulnerability finding formatted for presentation.
type ReportFindingItem struct {
	FindingID         uuid.UUID               `json:"finding_id"`
	Fingerprint       string                  `json:"fingerprint"`
	Title             string                  `json:"title"`
	Description       string                  `json:"description,omitempty"`
	Severity          string                  `json:"severity"`
	Status            string                  `json:"status"`
	CVSSScore         *float64                `json:"cvss_score,omitempty"`
	CWEID             string                  `json:"cwe_id,omitempty"`
	CVEIDs            []string                `json:"cve_ids,omitempty"`
	Endpoint          string                  `json:"endpoint"`
	RiskScore         *float64                `json:"risk_score,omitempty"`
	RiskBand          string                  `json:"risk_band,omitempty"`
	SanitizedEvidence []ReportEvidenceExcerpt `json:"sanitized_evidence,omitempty"`
}

// ReportEvidenceExcerpt models redacted, presentation-safe evidence excerpts.
type ReportEvidenceExcerpt struct {
	EvidenceID       uuid.UUID `json:"evidence_id"`
	EvidenceType     string    `json:"evidence_type"`
	SanitizedContent string    `json:"sanitized_content"`
	RedactionApplied bool      `json:"redaction_applied"`
}

// ReportRemediationItem provides actionable guidance for a finding.
type ReportRemediationItem struct {
	FindingID            uuid.UUID  `json:"finding_id"`
	TaskID               *uuid.UUID `json:"task_id,omitempty"`
	Title                string     `json:"title"`
	RecommendedAction    string     `json:"recommended_action"`
	TargetCompletionDate *time.Time `json:"target_completion_date,omitempty"`
	State                string     `json:"state,omitempty"`
}

// ReportProvenance captures compilation metadata, disclaimers, and integrity seals.
type ReportProvenance struct {
	EngineVersion string `json:"engine_version"`
	TemplateID    string `json:"template_id"`
	AuditHash     string `json:"audit_hash"`
	Disclaimer    string `json:"disclaimer"`
}

// Validate checks that the report fulfills all mandatory contract and security invariants.
func (r *ReportV1) Validate() error {
	if r.ReportID == uuid.Nil {
		return ErrInvalidReportID
	}
	if r.AssessmentID == uuid.Nil {
		return ErrInvalidAssessmentID
	}
	if r.TenantID == uuid.Nil {
		return ErrInvalidTenantID
	}
	if r.Title == "" {
		return ErrMissingReportTitle
	}
	if r.TemplateVersion == "" {
		return ErrMissingTemplateVersion
	}
	if r.ExecutionStatus.IsPartial && len(r.ExecutionStatus.PartialDisclosures) == 0 {
		return ErrPartialWithoutNotice
	}
	if r.SchemaVersion == "" {
		r.SchemaVersion = CurrentSchemaVersion
	}
	return nil
}

// ToJSON serializes the report into formatted JSON bytes.
func (r *ReportV1) ToJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(r, "", "  ")
}

// ParseReportV1 deserializes and validates a ReportV1 document from JSON.
func ParseReportV1(data []byte) (*ReportV1, error) {
	var r ReportV1
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("failed to parse report v1: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}
