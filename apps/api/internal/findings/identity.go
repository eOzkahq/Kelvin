package findings

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

var (
	ErrTenantMismatch  = errors.New("identity: tenant mismatch in finding resolution")
	ErrProjectMismatch = errors.New("identity: project mismatch in finding resolution")
	ErrEmptyTarget     = errors.New("identity: target asset must not be empty")
)

// ObservationInput encapsulates the raw inputs for finding identity resolution.
type ObservationInput struct {
	AssessmentID     uuid.UUID
	JobID            uuid.UUID
	ScannerID        string
	TargetAsset      string
	TargetEndpoint   string
	TemplateID       string
	CVEIDs           []string
	CWEID            string
	Title            string
	Severity         string
	Confidence       float64
	CVSSScore        *float64
	AffectedEndpoint string
	ScannerData      map[string]any
	Tags             []string
	EvidenceRefs     []string
	ObservedAt       time.Time
}

// IdentityResolutionResult captures the outcome of resolving an observation to a finding.
type IdentityResolutionResult struct {
	Finding     *PersistentFinding
	Observation *FindingObservation
	IsNew       bool
	Event       *FindingEvent
	IsAmbiguous bool
	Algorithm   string
}

// IdentityResolver coordinates deduplication and identity binding for finding observations.
type IdentityResolver struct{}

// NewIdentityResolver creates a new finding identity resolution engine.
func NewIdentityResolver() *IdentityResolver {
	return &IdentityResolver{}
}

// Resolve links an incoming observation to an existing persistent finding or provisions a new one.
// Deduplication strictly matches on (tenant_id, project_id, fingerprint); findings are never merged
// across tenants, projects, or based on fuzzy title/description similarity.
func (r *IdentityResolver) Resolve(
	tenantID, projectID uuid.UUID,
	input ObservationInput,
	existingFindings []*PersistentFinding,
	correlationID uuid.UUID,
) (*IdentityResolutionResult, error) {
	if input.TargetAsset == "" {
		return nil, ErrEmptyTarget
	}

	// Compute Algorithm v1 deterministic deduplication fingerprint
	fpResult, err := normalization.GenerateFingerprint(normalization.FingerprintInput{
		Asset:      input.TargetAsset,
		Endpoint:   input.TargetEndpoint,
		TemplateID: input.TemplateID,
		CVEIDs:     input.CVEIDs,
		CWEID:      input.CWEID,
		Title:      input.Title,
		Algorithm:  normalization.AlgorithmV1,
	})
	if err != nil {
		return nil, fmt.Errorf("identity: compute fingerprint failed: %w", err)
	}
	fingerprint := fpResult.Digest

	var matchedFinding *PersistentFinding
	var isAmbiguous bool
	vulnKey := normalization.DeriveVulnerabilityKey(input.TemplateID, input.CVEIDs, input.CWEID, input.Title)

	for _, f := range existingFindings {
		if f.TenantID != tenantID {
			continue // Strict tenant boundary isolation
		}
		if f.ProjectID != projectID {
			continue // Strict project boundary isolation
		}
		if f.Fingerprint == fingerprint {
			matchedFinding = f
			break
		}
		// Ambiguity check: Same asset and vulnerability key, but different location.
		// These are kept distinct and never merged automatically.
		fAsset := f.AffectedEndpoint
		if u, err := url.Parse(f.AffectedEndpoint); err == nil && u.Hostname() != "" {
			fAsset = u.Hostname()
		}
		var existingTemplateID string
		if f.ScannerData != nil {
			if tID, ok := f.ScannerData["template_id"].(string); ok {
				existingTemplateID = tID
			}
		}
		existingVulnKey := normalization.DeriveVulnerabilityKey(existingTemplateID, f.CVEIDs, f.CWEID, f.Title)
		if normalization.IsAmbiguousIdentity(fAsset, f.AffectedEndpoint, existingVulnKey, input.TargetAsset, input.TargetEndpoint, vulnKey) {
			isAmbiguous = true
		}
	}

	obsID, err := uuid.NewV7()
	if err != nil {
		obsID = uuid.New()
	}

	now := input.ObservedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Case 1: Match existing persistent finding (redetection / recurrence)
	if matchedFinding != nil {
		obs := &FindingObservation{
			ID:           obsID,
			TenantID:     tenantID,
			FindingID:    matchedFinding.ID,
			AssessmentID: input.AssessmentID,
			JobID:        input.JobID,
			ScannerID:    input.ScannerID,
			ObservedAt:   now,
			EvidenceRefs: input.EvidenceRefs,
			RawMetadata:  input.ScannerData,
			CreatedAt:    time.Now().UTC(),
		}

		event, err := IngestObservation(matchedFinding, *obs, correlationID)
		if err != nil {
			return nil, err
		}

		return &IdentityResolutionResult{
			Finding:     matchedFinding,
			Observation: obs,
			IsNew:       false,
			Event:       event,
			IsAmbiguous: false,
			Algorithm:   fpResult.Algorithm,
		}, nil
	}

	// Case 2: New persistent finding
	findingID, err := uuid.NewV7()
	if err != nil {
		findingID = uuid.New()
	}

	endpoint := input.AffectedEndpoint
	if endpoint == "" {
		endpoint = input.TargetEndpoint
	}

	scannerData := make(map[string]any)
	for k, v := range input.ScannerData {
		scannerData[k] = v
	}
	if input.TemplateID != "" {
		scannerData["template_id"] = input.TemplateID
	}

	newFinding := &PersistentFinding{
		ID:               findingID,
		TenantID:         tenantID,
		ProjectID:        projectID,
		AssessmentID:     input.AssessmentID,
		JobID:            input.JobID,
		Fingerprint:      fingerprint,
		Title:            input.Title,
		Severity:         input.Severity,
		Confidence:       input.Confidence,
		CVSSScore:        input.CVSSScore,
		CWEID:            input.CWEID,
		CVEIDs:           input.CVEIDs,
		Status:           StatusOpen,
		AffectedEndpoint: endpoint,
		ScannerData:      scannerData,
		Tags:             input.Tags,
		FirstSeenAt:      now,
		LastSeenAt:       now,
		FirstJobID:       input.JobID,
		LastJobID:        &input.JobID,
		OccurrenceCount:  1,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	obs := &FindingObservation{
		ID:           obsID,
		TenantID:     tenantID,
		FindingID:    newFinding.ID,
		AssessmentID: input.AssessmentID,
		JobID:        input.JobID,
		ScannerID:    input.ScannerID,
		ObservedAt:   now,
		EvidenceRefs: input.EvidenceRefs,
		RawMetadata:  input.ScannerData,
		CreatedAt:    time.Now().UTC(),
	}

	event := &FindingEvent{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     newFinding.ID,
		ToStatus:      StatusOpen,
		EventType:     EventCreated,
		Note:          fmt.Sprintf("First detected by scanner %s in job %s", input.ScannerID, input.JobID),
		CorrelationID: correlationID,
		CreatedAt:     time.Now().UTC(),
	}

	return &IdentityResolutionResult{
		Finding:     newFinding,
		Observation: obs,
		IsNew:       true,
		Event:       event,
		IsAmbiguous: isAmbiguous,
		Algorithm:   fpResult.Algorithm,
	}, nil
}
