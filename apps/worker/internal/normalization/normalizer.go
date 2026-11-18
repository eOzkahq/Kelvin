package normalization

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
	commonnorm "github.com/kelvin/kelvin/packages/common/normalization"
)

// Re-export common canonical models for backward compatibility and cross-boundary unification.
type (
	Target           = commonnorm.Target
	Vulnerability    = commonnorm.Vulnerability
	CVSSInfo         = commonnorm.CVSSInfo
	Remediation      = commonnorm.Remediation
	EvidenceArtifact = commonnorm.EvidenceArtifact
	Evidence         = commonnorm.Evidence
	ScannerInfo      = commonnorm.ScannerInfo
	CanonicalFinding = commonnorm.CanonicalFinding
)

// Context carries run-level identifiers into finding normalization.
type Context struct {
	AssessmentID  string
	RunID         string
	CorrelationID string
}

// Normalizer transforms and standardizes scanner finding payloads.
type Normalizer struct{}

// NewNormalizer creates a new shared finding normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize parses, standardizes, validates, and fingerprints a finding into finding.v1.json format.
func (n *Normalizer) Normalize(raw []byte, ctx Context) (CanonicalFinding, error) {
	if err := parserguard.ValidatePayload(raw); err != nil {
		return CanonicalFinding{}, fmt.Errorf("normalization: invalid payload: %w", err)
	}

	if err := parserguard.CheckJSONNestingDepth(raw, parserguard.MaxNestingDepth); err != nil {
		return CanonicalFinding{}, fmt.Errorf("normalization: nesting depth exceeded: %w", err)
	}

	var finding CanonicalFinding
	if err := json.Unmarshal(raw, &finding); err != nil {
		return CanonicalFinding{}, fmt.Errorf("normalization: unmarshal finding: %w", err)
	}

	if finding.SchemaVersion == "" {
		finding.SchemaVersion = "1.0"
	}

	// Assign ID if absent
	if finding.ID == "" {
		newID, err := uuid.NewV7()
		if err == nil {
			finding.ID = newID.String()
		} else {
			finding.ID = uuid.NewString()
		}
	}

	// Canonicalize vulnerability indicators
	if finding.Vulnerability.CWEID != "" {
		finding.Vulnerability.CWEID = NormalizeCWE(finding.Vulnerability.CWEID)
	}
	if len(finding.Vulnerability.CVEIDs) > 0 {
		finding.Vulnerability.CVEIDs = NormalizeCVEs(finding.Vulnerability.CVEIDs)
	} else if finding.Vulnerability.CVEIDs == nil {
		finding.Vulnerability.CVEIDs = []string{}
	}
	if finding.Vulnerability.CVSS != nil {
		if finding.Vulnerability.CVSS.Score < 0.0 {
			finding.Vulnerability.CVSS.Score = 0.0
		} else if finding.Vulnerability.CVSS.Score > 10.0 {
			finding.Vulnerability.CVSS.Score = 10.0
		}
	}

	// Normalize severity
	sev := strings.ToUpper(strings.TrimSpace(finding.Severity))
	switch sev {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL":
		finding.Severity = sev
	case "INFO":
		finding.Severity = "INFORMATIONAL"
	default:
		return CanonicalFinding{}, fmt.Errorf("normalization: unsupported severity %q", finding.Severity)
	}

	// Bounded confidence
	if finding.Confidence < 0.0 {
		finding.Confidence = 0.0
	} else if finding.Confidence > 1.0 {
		finding.Confidence = 1.0
	}

	// Normalize target
	finding.Target.Asset = NormalizeAsset(finding.Target.Asset)
	if finding.Target.Asset == "" {
		return CanonicalFinding{}, fmt.Errorf("normalization: target asset is required")
	}

	if finding.Target.Endpoint != "" {
		normEndpoint, err := NormalizeEndpoint(finding.Target.Endpoint)
		if err != nil {
			return CanonicalFinding{}, fmt.Errorf("normalization: invalid endpoint: %w", err)
		}
		finding.Target.Endpoint = normEndpoint
	}

	// Compute deterministic fingerprint if absent or extract from tagged format
	if strings.HasPrefix(finding.Fingerprint, "fp_") {
		if _, digest, err := ParseTaggedFingerprint(finding.Fingerprint); err == nil {
			finding.Fingerprint = digest
		}
	}
	if finding.Fingerprint == "" {
		fp, _, err := ComputeFingerprint(
			finding.Target.Asset,
			finding.Target.Endpoint,
			finding.Vulnerability.TemplateID,
			finding.Vulnerability.CVEIDs,
			finding.Vulnerability.CWEID,
			finding.Title,
		)
		if err != nil {
			return CanonicalFinding{}, fmt.Errorf("normalization: compute fingerprint: %w", err)
		}
		finding.Fingerprint = fp
	}

	// Ensure standard defaults
	if strings.TrimSpace(finding.DiscoveredAt) == "" {
		finding.DiscoveredAt = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(finding.Status) == "" {
		finding.Status = "OPEN"
	}
	if finding.Tags == nil {
		finding.Tags = []string{}
	}
	if finding.ReproductionSteps == nil {
		finding.ReproductionSteps = []string{}
	}

	// Correlate scanner run ID
	if ctx.RunID != "" {
		finding.Scanner.RunID = ctx.RunID
	}

	// Correlate assessment in scanner_meta extension
	if ctx.AssessmentID != "" {
		if finding.ScannerMeta == nil {
			finding.ScannerMeta = make(map[string]any)
		}
		finding.ScannerMeta["kelvin.assessment_id"] = ctx.AssessmentID
	}

	// Ensure evidence attestation
	for i := range finding.Evidence {
		if finding.Evidence[i].RedactedFields == nil {
			finding.Evidence[i].RedactedFields = []string{}
		}
	}

	// Re-serialize and validate through schema validation gate
	encoded, err := json.Marshal(finding)
	if err != nil {
		return CanonicalFinding{}, fmt.Errorf("normalization: serialize canonical finding: %w", err)
	}

	if err := adapters.ValidateFindings(encoded); err != nil {
		return CanonicalFinding{}, fmt.Errorf("normalization: finding schema validation gate failed: %w", err)
	}

	return finding, nil
}

// NormalizeBatch normalizes a slice of findings, collecting accepted findings and individual errors.
func (n *Normalizer) NormalizeBatch(rawFindings []json.RawMessage, ctx Context) ([]CanonicalFinding, []error) {
	accepted := make([]CanonicalFinding, 0, len(rawFindings))
	errs := make([]error, 0)

	for i, raw := range rawFindings {
		norm, err := n.Normalize(raw, ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("finding %d: %w", i, err))
			continue
		}
		accepted = append(accepted, norm)
	}

	return accepted, errs
}
