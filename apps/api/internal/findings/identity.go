package findings

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

var (
	ErrTenantMismatch  = errors.New("identity: tenant mismatch in finding resolution")
	ErrProjectMismatch = errors.New("identity: project mismatch in finding resolution")
	ErrEmptyTarget     = errors.New("identity: target asset must not be empty")

	numericPathSegment = regexp.MustCompile(`/\d+(/|$)`)
	uuidPathSegment    = regexp.MustCompile(`/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(/|$)`)
)

// NormalizeDynamicPath normalizes dynamic path segments (IDs, UUIDs) and strips query params for recurring matching.
func NormalizeDynamicPath(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Path == "" {
		return endpoint
	}
	p := u.Path
	p = uuidPathSegment.ReplaceAllString(p, "/{uuid}$1")
	p = numericPathSegment.ReplaceAllString(p, "/{id}$1")
	u.Path = p
	u.RawQuery = ""
	return u.String()
}

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
	Finding         *PersistentFinding
	Observation     *FindingObservation
	IsNew           bool
	Event           *FindingEvent
	IsAmbiguous     bool
	Algorithm       string
	MatchReason     string
	MatchConfidence float64
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
	matchAlgorithm := fpResult.Algorithm
	matchConfidence := 1.0
	matchReason := "Exact deterministic fingerprint match (Algorithm v1)"
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
			if NormalizeDynamicPath(f.AffectedEndpoint) != NormalizeDynamicPath(input.TargetEndpoint) {
				isAmbiguous = true
			}
		}
	}

	// Dynamic path recurrence matching: handle dynamic URL IDs/UUIDs across assessments conservatively
	if matchedFinding == nil && !isAmbiguous && input.TargetEndpoint != "" {
		normInputDynamic := NormalizeDynamicPath(input.TargetEndpoint)
		normInputAsset := normalization.NormalizeAsset(input.TargetAsset)

		for _, f := range existingFindings {
			if f.TenantID != tenantID || f.ProjectID != projectID {
				continue
			}
			fAsset := f.AffectedEndpoint
			if u, err := url.Parse(f.AffectedEndpoint); err == nil && u.Hostname() != "" {
				fAsset = u.Hostname()
			}
			if normalization.NormalizeAsset(fAsset) != normInputAsset {
				continue
			}

			var existingTemplateID string
			if f.ScannerData != nil {
				if tID, ok := f.ScannerData["template_id"].(string); ok {
					existingTemplateID = tID
				}
			}
			existingVulnKey := normalization.DeriveVulnerabilityKey(existingTemplateID, f.CVEIDs, f.CWEID, f.Title)
			if existingVulnKey == vulnKey && f.AffectedEndpoint != "" {
				normExistingDynamic := NormalizeDynamicPath(f.AffectedEndpoint)
				if normInputDynamic == normExistingDynamic {
					matchedFinding = f
					matchAlgorithm = "v1-dynamic-path"
					matchConfidence = 0.95
					matchReason = "Dynamic path parameterized match ({id}/{uuid})"
					break
				}
			}
		}
	}

	if matchedFinding == nil {
		matchConfidence = 0.0
		if isAmbiguous {
			matchReason = "Uncertain match: distinct endpoint routes; preserved as separate findings"
		} else {
			matchReason = "No matching prior finding discovered in project scope"
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

	rawMeta := make(map[string]any, len(input.ScannerData)+1)
	for k, v := range input.ScannerData {
		rawMeta[k] = v
	}
	decisionMeta := map[string]any{
		"is_recurrent":     matchedFinding != nil,
		"algorithm":        matchAlgorithm,
		"match_reason":     matchReason,
		"match_confidence": matchConfidence,
	}
	if matchedFinding != nil {
		decisionMeta["existing_finding_id"] = matchedFinding.ID.String()
	}
	rawMeta["match_decision"] = decisionMeta

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
			RawMetadata:  rawMeta,
			CreatedAt:    time.Now().UTC(),
		}

		if matchedFinding.RiskScore == nil {
			riskEngine := NewRiskEngine()
			if riskRes, err := riskEngine.Compute(matchedFinding); err == nil && riskRes != nil {
				matchedFinding.RiskScore = &riskRes.RiskScore
				matchedFinding.RiskPriorityBand = riskRes.PriorityBand
				matchedFinding.RiskFactors = riskRes.InputFactors
			}
		}

		event, err := IngestObservation(matchedFinding, *obs, correlationID)
		if err != nil {
			return nil, err
		}

		return &IdentityResolutionResult{
			Finding:         matchedFinding,
			Observation:     obs,
			IsNew:           false,
			Event:           event,
			IsAmbiguous:     false,
			Algorithm:       matchAlgorithm,
			MatchReason:     matchReason,
			MatchConfidence: matchConfidence,
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

	riskEngine := NewRiskEngine()
	if riskRes, err := riskEngine.Compute(newFinding); err == nil && riskRes != nil {
		newFinding.RiskScore = &riskRes.RiskScore
		newFinding.RiskPriorityBand = riskRes.PriorityBand
		newFinding.RiskFactors = riskRes.InputFactors
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
		RawMetadata:  rawMeta,
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
		Finding:         newFinding,
		Observation:     obs,
		IsNew:           true,
		Event:           event,
		IsAmbiguous:     isAmbiguous,
		Algorithm:       matchAlgorithm,
		MatchReason:     matchReason,
		MatchConfidence: matchConfidence,
	}, nil
}
