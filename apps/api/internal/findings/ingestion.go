package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

var (
	ErrAssessmentNotFound       = errors.New("ingestion: assessment not found or inaccessible")
	ErrAssessmentTenantMismatch = errors.New("ingestion: assessment tenant mismatch")
	ErrAssessmentCancelled      = errors.New("ingestion: assessment was cancelled or invalid")
	ErrAssessmentFailed         = errors.New("ingestion: assessment terminated with critical failure")
	ErrEmptyBatch               = errors.New("ingestion: finding batch is empty")
	ErrUntrustedResult          = errors.New("ingestion: finding payload failed schema/integrity checks")
	ErrInvalidFindingData       = errors.New("ingestion: invalid finding data")
)

// AssessmentContext contains verified assessment and job metadata for ingestion.
type AssessmentContext struct {
	TenantID     uuid.UUID
	ProjectID    uuid.UUID
	AssessmentID uuid.UUID
	JobID        uuid.UUID
	Status       string // e.g. "COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED"
	TargetAsset  string
}

// IngestionSummary summarizes the outcome of processing a batch of findings.
type IngestionSummary struct {
	TotalProcessed           int
	NewFindings              int
	Redetected               int
	Replayed                 int
	SameAssessmentDuplicates int
	AmbiguousCount           int
	Observations             []*FindingObservation
	CreatedEvents            []*FindingEvent
	Decisions                []DeduplicationDecision
}

// AssessmentValidator checks that the target assessment exists, matches the tenant, and is in a valid state.
type AssessmentValidator interface {
	ValidateAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*AssessmentContext, error)
}

// FindingRepository manages persistence for findings, observations, and audit events.
type FindingRepository interface {
	GetFindingsByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]*PersistentFinding, error)
	GetFindingByID(ctx context.Context, tenantID, findingID uuid.UUID) (*PersistentFinding, error)
	GetObservationsByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*FindingObservation, error)
	ObservationExists(ctx context.Context, tenantID, assessmentID, findingID uuid.UUID) (bool, error)
	SaveFinding(ctx context.Context, finding *PersistentFinding) error
	SaveObservation(ctx context.Context, obs *FindingObservation) error
	SaveEvent(ctx context.Context, event *FindingEvent) error
}

type timelineRecorder interface {
	RecordTimelineEvent(ctx context.Context, entry *TimelineEntry) error
}

// IngestionEventPublisher notifies the system bus when findings are ingested.
type IngestionEventPublisher interface {
	PublishFindingsIngested(ctx context.Context, tenantID, assessmentID uuid.UUID, summary IngestionSummary) error
}

// IngestionService orchestrates intake of validated canonical scanner results into persistent findings and observations.
type IngestionService struct {
	resolver     *IdentityResolver
	deduplicator *InAssessmentDeduplicator
	validator    AssessmentValidator
	repo         FindingRepository
	publisher    IngestionEventPublisher
}

// NewIngestionService constructs a finding ingestion service.
func NewIngestionService(
	validator AssessmentValidator,
	repo FindingRepository,
	publisher IngestionEventPublisher,
) *IngestionService {
	return &IngestionService{
		resolver:     NewIdentityResolver(),
		deduplicator: NewInAssessmentDeduplicator(),
		validator:    validator,
		repo:         repo,
		publisher:    publisher,
	}
}

// IngestBatch ingests a slice of normalized Phase 2 canonical findings for an assessment.
func (s *IngestionService) IngestBatch(
	ctx context.Context,
	tenantID, assessmentID uuid.UUID,
	findings []normalization.CanonicalFinding,
	correlationID uuid.UUID,
) (*IngestionSummary, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantMismatch
	}
	if assessmentID == uuid.Nil {
		return nil, ErrAssessmentNotFound
	}

	// 1. Validate assessment lifecycle and tenant authorization
	asmtCtx, err := s.validator.ValidateAssessment(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, err
	}
	if asmtCtx.TenantID != tenantID {
		return nil, ErrAssessmentTenantMismatch
	}

	// Reject cancelled or invalid assessment state
	if asmtCtx.Status == "CANCELLED" {
		return nil, ErrAssessmentCancelled
	}
	if asmtCtx.Status == "FAILED" {
		return nil, ErrAssessmentFailed
	}

	isPartial := asmtCtx.Status == "COMPLETED_WITH_WARNINGS"

	// 2. In-Assessment Deduplication (P3-12)
	dedupedFindings, decisions, err := s.deduplicator.Deduplicate(findings)
	if err != nil {
		return nil, fmt.Errorf("ingestion: deduplicate findings failed: %w", err)
	}

	// 3. Fetch existing persistent findings for in-memory deduplication lookup
	existingFindings, err := s.repo.GetFindingsByProject(ctx, tenantID, asmtCtx.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("ingestion: fetch existing project findings failed: %w", err)
	}

	// Working set of findings updated during this batch
	currentFindings := make([]*PersistentFinding, len(existingFindings))
	copy(currentFindings, existingFindings)

	summary := &IngestionSummary{
		Observations:             make([]*FindingObservation, 0, len(dedupedFindings)),
		CreatedEvents:            make([]*FindingEvent, 0, len(dedupedFindings)),
		SameAssessmentDuplicates: len(findings) - len(dedupedFindings),
		Decisions:                decisions,
	}

	for _, f := range dedupedFindings {
		if f.Target.Asset == "" || f.Title == "" || f.Severity == "" {
			return nil, fmt.Errorf("%w: missing required target, title, or severity", ErrInvalidFindingData)
		}

		observedAt := time.Now().UTC()
		if f.DiscoveredAt != "" {
			if parsed, parseErr := time.Parse(time.RFC3339, f.DiscoveredAt); parseErr == nil {
				observedAt = parsed
			}
		}

		evidenceRefs := make([]string, 0, len(f.Evidence))
		for _, ev := range f.Evidence {
			if ev.ID != "" {
				evidenceRefs = append(evidenceRefs, ev.ID)
			} else if ev.ChecksumSHA256 != "" {
				evidenceRefs = append(evidenceRefs, ev.ChecksumSHA256)
			} else if ev.ContentRedacted != "" {
				sum := sha256.Sum256([]byte(ev.ContentRedacted))
				evidenceRefs = append(evidenceRefs, hex.EncodeToString(sum[:]))
			}
		}

		meta := make(map[string]any)
		for k, v := range f.ScannerMeta {
			meta[k] = v
		}
		// Preserve scanner execution provenance
		meta["scanner_name"] = f.Scanner.Name
		meta["adapter_version"] = f.Scanner.AdapterVersion
		if f.Scanner.EngineVersion != "" {
			meta["engine_version"] = f.Scanner.EngineVersion
		}
		if f.Scanner.RunID != "" {
			meta["run_id"] = f.Scanner.RunID
		}
		if isPartial {
			meta["partial_scan"] = true
		}

		var cvssScore *float64
		if f.Vulnerability.CVSS != nil {
			s := f.Vulnerability.CVSS.Score
			cvssScore = &s
		}

		tags := make([]string, len(f.Tags))
		copy(tags, f.Tags)
		if isPartial {
			tags = append(tags, "partial-assessment")
		}

		input := ObservationInput{
			AssessmentID:     asmtCtx.AssessmentID,
			JobID:            asmtCtx.JobID,
			ScannerID:        f.Scanner.Name,
			TargetAsset:      f.Target.Asset,
			TargetEndpoint:   f.Target.Endpoint,
			TemplateID:       f.Vulnerability.TemplateID,
			CVEIDs:           f.Vulnerability.CVEIDs,
			CWEID:            f.Vulnerability.CWEID,
			Title:            f.Title,
			Severity:         f.Severity,
			Confidence:       f.Confidence,
			CVSSScore:        cvssScore,
			AffectedEndpoint: f.Target.Endpoint,
			ScannerData:      meta,
			Tags:             tags,
			EvidenceRefs:     evidenceRefs,
			ObservedAt:       observedAt,
		}

		// Idempotency Probe (P3-06): check if an observation for this finding in this assessment already exists
		fpResult, err := normalization.GenerateFingerprint(normalization.FingerprintInput{
			Asset:      f.Target.Asset,
			Endpoint:   f.Target.Endpoint,
			TemplateID: f.Vulnerability.TemplateID,
			CVEIDs:     f.Vulnerability.CVEIDs,
			CWEID:      f.Vulnerability.CWEID,
			Title:      f.Title,
			Algorithm:  normalization.AlgorithmV1,
		})
		if err != nil {
			return nil, fmt.Errorf("ingestion: fingerprint generation failed: %w", err)
		}

		var existingMatch *PersistentFinding
		for _, ef := range currentFindings {
			if ef.TenantID == tenantID && ef.ProjectID == asmtCtx.ProjectID && ef.Fingerprint == fpResult.Digest {
				existingMatch = ef
				break
			}
		}

		if existingMatch != nil {
			exists, err := s.repo.ObservationExists(ctx, tenantID, asmtCtx.AssessmentID, existingMatch.ID)
			if err != nil {
				return nil, fmt.Errorf("ingestion: check observation idempotency failed: %w", err)
			}
			if exists {
				// Repeated delivery / retry of the same assessment result.
				// Skip duplicate observation insert and do not mutate finding or occurrence count.
				summary.Replayed++
				summary.TotalProcessed++
				continue
			}
		}

		res, err := s.resolver.Resolve(tenantID, asmtCtx.ProjectID, input, currentFindings, correlationID)
		if err != nil {
			return nil, fmt.Errorf("ingestion: resolve finding identity failed: %w", err)
		}

		if err := s.repo.SaveFinding(ctx, res.Finding); err != nil {
			return nil, fmt.Errorf("ingestion: save finding failed: %w", err)
		}

		if err := s.repo.SaveObservation(ctx, res.Observation); err != nil {
			return nil, fmt.Errorf("ingestion: save observation failed: %w", err)
		}

		if res.Event != nil {
			if err := s.repo.SaveEvent(ctx, res.Event); err != nil {
				return nil, fmt.Errorf("ingestion: save event failed: %w", err)
			}
			summary.CreatedEvents = append(summary.CreatedEvents, res.Event)
		}

		if tr, ok := s.repo.(timelineRecorder); ok {
			if res.IsNew {
				_ = tr.RecordTimelineEvent(ctx, &TimelineEntry{
					TenantID:      res.Finding.TenantID,
					FindingID:     res.Finding.ID,
					EventType:     TimelineEventFindingCreated,
					Payload: map[string]any{
						"title":       res.Finding.Title,
						"severity":    string(res.Finding.Severity),
						"fingerprint": res.Finding.Fingerprint,
					},
					CorrelationID: correlationID,
					CreatedAt:     res.Finding.CreatedAt,
				})
			}
			_ = tr.RecordTimelineEvent(ctx, &TimelineEntry{
				TenantID:      res.Observation.TenantID,
				FindingID:     res.Observation.FindingID,
				EventType:     TimelineEventObservationRecorded,
				Payload: map[string]any{
					"assessment_id": res.Observation.AssessmentID.String(),
					"job_id":        res.Observation.JobID.String(),
					"scanner_id":    res.Observation.ScannerID,
				},
				CorrelationID: correlationID,
				CreatedAt:     res.Observation.ObservedAt,
			})
		}

		summary.Observations = append(summary.Observations, res.Observation)
		summary.TotalProcessed++

		if res.IsNew {
			summary.NewFindings++
			currentFindings = append(currentFindings, res.Finding)
		} else {
			summary.Redetected++
		}

		if res.IsAmbiguous {
			summary.AmbiguousCount++
		}
	}

	if s.publisher != nil {
		_ = s.publisher.PublishFindingsIngested(ctx, tenantID, asmtCtx.AssessmentID, *summary)
	}

	return summary, nil
}

