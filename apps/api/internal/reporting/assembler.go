package reporting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAssessmentNotFound = errors.New("reporting: assessment not found")
	ErrTenantMismatch     = errors.New("reporting: tenant boundary violation")
	ErrSnapshotNotFound   = errors.New("reporting: report snapshot not found")
)

// AssessmentRecord represents the assessment execution metadata needed for report assembly.
type AssessmentRecord struct {
	ID                 uuid.UUID `json:"id"`
	TenantID           uuid.UUID `json:"tenant_id"`
	ProjectID          uuid.UUID `json:"project_id"`
	Targets            []string  `json:"targets"`
	Scanners           []string  `json:"scanners"`
	Profile            string    `json:"profile"`
	Status             string    `json:"status"` // "COMPLETED", "PARTIAL", "FAILED"
	IsPartial          bool      `json:"is_partial"`
	StartedAt          time.Time `json:"started_at"`
	CompletedAt        time.Time `json:"completed_at"`
	PartialDisclosures []string  `json:"partial_disclosures"`
	Limitations        []string  `json:"limitations"`
}

// ReportSnapshot represents an immutable point-in-time report record stored in PostgreSQL.
type ReportSnapshot struct {
	ID              uuid.UUID `json:"id"`
	TenantID        uuid.UUID `json:"tenant_id"`
	AssessmentID    uuid.UUID `json:"assessment_id"`
	ReportID        uuid.UUID `json:"report_id"`
	Title           string    `json:"title"`
	SchemaVersion   string    `json:"schema_version"`
	TemplateVersion string    `json:"template_version"`
	SnapshotData    *ReportV1 `json:"snapshot_data"`
	CreatedAt       time.Time `json:"created_at"`
}

// AssessmentDataSource retrieves assessment metadata within tenant boundaries.
type AssessmentDataSource interface {
	GetAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*AssessmentRecord, error)
}

// FindingDataSource retrieves point-in-time findings and sanitized evidence for an assessment.
type FindingDataSource interface {
	GetAssessmentFindings(ctx context.Context, tenantID, assessmentID uuid.UUID) ([]ReportFindingItem, error)
}

// RemediationDataSource retrieves active remediation tasks for findings.
type RemediationDataSource interface {
	GetRemediationGuidance(ctx context.Context, tenantID, findingID uuid.UUID) ([]ReportRemediationItem, error)
}

// SnapshotRepository defines persistence for immutable report snapshots.
type SnapshotRepository interface {
	SaveSnapshot(ctx context.Context, snapshot *ReportSnapshot) error
	GetSnapshot(ctx context.Context, tenantID, reportID uuid.UUID) (*ReportSnapshot, error)
}

// MemorySnapshotRepository provides thread-safe in-memory storage for report snapshots.
type MemorySnapshotRepository struct {
	mu        sync.RWMutex
	snapshots map[uuid.UUID]ReportSnapshot
}

// NewMemorySnapshotRepository initializes an in-memory snapshot repository.
func NewMemorySnapshotRepository() *MemorySnapshotRepository {
	return &MemorySnapshotRepository{
		snapshots: make(map[uuid.UUID]ReportSnapshot),
	}
}

func (m *MemorySnapshotRepository) SaveSnapshot(_ context.Context, snapshot *ReportSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if snapshot == nil || snapshot.ReportID == uuid.Nil {
		return errors.New("invalid snapshot")
	}
	m.snapshots[snapshot.ReportID] = *snapshot
	return nil
}

func (m *MemorySnapshotRepository) GetSnapshot(_ context.Context, tenantID, reportID uuid.UUID) (*ReportSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, exists := m.snapshots[reportID]
	if !exists {
		return nil, ErrSnapshotNotFound
	}
	if s.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	copied := s
	return &copied, nil
}

// ReportAssemblyService coordinates the collection and freezing of assessment data into ReportV1 documents.
type ReportAssemblyService struct {
	assessmentSource AssessmentDataSource
	findingSource    FindingDataSource
	remediationSource RemediationDataSource
	snapshotRepo     SnapshotRepository
}

// NewReportAssemblyService constructs a report assembly service.
func NewReportAssemblyService(
	assessmentSource AssessmentDataSource,
	findingSource FindingDataSource,
	remediationSource RemediationDataSource,
	snapshotRepo SnapshotRepository,
) *ReportAssemblyService {
	return &ReportAssemblyService{
		assessmentSource: assessmentSource,
		findingSource:    findingSource,
		remediationSource: remediationSource,
		snapshotRepo:     snapshotRepo,
	}
}

// AssembleReport collects a frozen, point-in-time snapshot of assessment data and persists it.
func (s *ReportAssemblyService) AssembleReport(
	ctx context.Context,
	tenantID, assessmentID uuid.UUID,
	title string,
	templateVersion string,
) (*ReportV1, error) {
	if tenantID == uuid.Nil {
		return nil, ErrInvalidTenantID
	}
	if assessmentID == uuid.Nil {
		return nil, ErrInvalidAssessmentID
	}
	if title == "" {
		return nil, ErrMissingReportTitle
	}
	if templateVersion == "" {
		templateVersion = DefaultTemplateID
	}

	// 1. Fetch Assessment Metadata & verify tenant boundary
	assessment, err := s.assessmentSource.GetAssessment(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch assessment: %w", err)
	}
	if assessment.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	// 2. Fetch Findings Snapshot
	findings, err := s.findingSource.GetAssessmentFindings(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch findings: %w", err)
	}

	// Ensure all evidence in findings is marked as sanitized (ADR-0005)
	for i := range findings {
		for j := range findings[i].SanitizedEvidence {
			findings[i].SanitizedEvidence[j].RedactionApplied = true
		}
	}

	// 3. Fetch Remediation Guidance
	var allRemediations []ReportRemediationItem
	if s.remediationSource != nil {
		for _, f := range findings {
			items, err := s.remediationSource.GetRemediationGuidance(ctx, tenantID, f.FindingID)
			if err == nil && len(items) > 0 {
				allRemediations = append(allRemediations, items...)
			}
		}
	}

	// 4. Calculate Aggregate Metrics
	severityBreakdown := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}
	priorityBreakdown := map[string]int{
		"P1": 0,
		"P2": 0,
		"P3": 0,
		"P4": 0,
		"P5": 0,
	}

	var maxRiskScore float64
	for _, f := range findings {
		sev := f.Severity
		if _, exists := severityBreakdown[sev]; exists {
			severityBreakdown[sev]++
		}
		if f.RiskBand != "" {
			if _, exists := priorityBreakdown[f.RiskBand]; exists {
				priorityBreakdown[f.RiskBand]++
			}
		}
		if f.RiskScore != nil && *f.RiskScore > maxRiskScore {
			maxRiskScore = *f.RiskScore
		}
	}

	postureBand := "CLEAN"
	if severityBreakdown["CRITICAL"] > 0 {
		postureBand = "CRITICAL"
	} else if severityBreakdown["HIGH"] > 0 {
		postureBand = "HIGH"
	} else if severityBreakdown["MEDIUM"] > 0 {
		postureBand = "MEDIUM"
	} else if severityBreakdown["LOW"] > 0 {
		postureBand = "LOW"
	}

	executiveNarrative := fmt.Sprintf(
		"Assessment completed with %d total findings detected across %d target(s). Posture rating: %s.",
		len(findings), len(assessment.Targets), postureBand,
	)

	// 5. Construct ReportV1 document
	reportID := uuid.New()
	now := time.Now().UTC()

	report := &ReportV1{
		SchemaVersion:   CurrentSchemaVersion,
		ReportID:        reportID,
		AssessmentID:    assessmentID,
		TenantID:        tenantID,
		Title:           title,
		GeneratedAt:     now,
		TemplateVersion: templateVersion,
		Summary: ReportSummary{
			OverallRiskScore:   maxRiskScore,
			PostureBand:        postureBand,
			TotalFindings:      len(findings),
			CriticalCount:      severityBreakdown["CRITICAL"],
			HighCount:          severityBreakdown["HIGH"],
			MediumCount:        severityBreakdown["MEDIUM"],
			LowCount:           severityBreakdown["LOW"],
			InfoCount:          severityBreakdown["INFO"],
			ExecutiveNarrative: executiveNarrative,
		},
		Scope: ReportScope{
			Targets:  assessment.Targets,
			Scanners: assessment.Scanners,
			Profile:  assessment.Profile,
		},
		ExecutionStatus: ReportExecutionStatus{
			Status:             assessment.Status,
			IsPartial:          assessment.IsPartial,
			StartedAt:          assessment.StartedAt,
			CompletedAt:        assessment.CompletedAt,
			PartialDisclosures: assessment.PartialDisclosures,
			Limitations:        assessment.Limitations,
		},
		FindingsSummary: ReportFindingsSummary{
			SeverityBreakdown: severityBreakdown,
			PriorityBreakdown: priorityBreakdown,
		},
		Findings:            findings,
		RemediationGuidance: allRemediations,
		Provenance: ReportProvenance{
			EngineVersion: "kelvin-report-assembler-v1",
			TemplateID:    templateVersion,
			AuditHash:     "", // computed below
			Disclaimer:    "This report provides an immutable point-in-time security audit snapshot. Subsequent scan results or environment changes may alter findings.",
		},
	}

	// Calculate cryptographic integrity audit hash of assembled content
	canonicalBytes, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize report: %w", err)
	}
	hash := sha256.Sum256(canonicalBytes)
	report.Provenance.AuditHash = hex.EncodeToString(hash[:])

	if err := report.Validate(); err != nil {
		return nil, fmt.Errorf("assembled report validation failed: %w", err)
	}

	// 6. Persist Immutable Snapshot
	if s.snapshotRepo != nil {
		snapshot := &ReportSnapshot{
			ID:              uuid.New(),
			TenantID:        tenantID,
			AssessmentID:    assessmentID,
			ReportID:        reportID,
			Title:           title,
			SchemaVersion:   CurrentSchemaVersion,
			TemplateVersion: templateVersion,
			SnapshotData:    report,
			CreatedAt:       now,
		}
		if err := s.snapshotRepo.SaveSnapshot(ctx, snapshot); err != nil {
			return nil, fmt.Errorf("failed to save report snapshot: %w", err)
		}
	}

	return report, nil
}
