package normalization

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

// Target represents the affected asset and endpoint.
type Target struct {
	Asset    string `json:"asset"`
	Endpoint string `json:"endpoint,omitempty"`
	Method   string `json:"method,omitempty"`
}

// Vulnerability represents vulnerability taxonomy metadata.
type Vulnerability struct {
	TemplateID string    `json:"template_id,omitempty"`
	CWEID      string    `json:"cwe_id,omitempty"`
	CVEIDs     []string  `json:"cve_ids,omitempty"`
	CVSS       *CVSSInfo `json:"cvss,omitempty"`
}

// CVSSInfo represents CVSS score and vector metadata.
type CVSSInfo struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector,omitempty"`
}

// Remediation describes guidance for resolving the vulnerability.
type Remediation struct {
	Summary             string   `json:"summary"`
	References          []string `json:"references,omitempty"`
	PatchRecommendation string   `json:"patch_recommendation,omitempty"`
}

// EvidenceArtifact references large artifacts stored out-of-band.
type EvidenceArtifact struct {
	ChecksumSHA256 string `json:"checksum_sha256"`
	SizeBytes      int64  `json:"size_bytes"`
	ContentType    string `json:"content_type"`
}

// Evidence represents a validated, redacted evidence item.
type Evidence struct {
	ID              string            `json:"id,omitempty"`
	Type            string            `json:"type"`
	ContentType     string            `json:"content_type,omitempty"`
	ContentRedacted string            `json:"content_redacted,omitempty"`
	SizeBytes       int64             `json:"size_bytes,omitempty"`
	ChecksumSHA256  string            `json:"checksum_sha256,omitempty"`
	RedactedFields  []string          `json:"redacted_fields"`
	Artifact        *EvidenceArtifact `json:"artifact,omitempty"`
}

// ScannerInfo describes the engine and adapter producing the finding.
type ScannerInfo struct {
	Name           string `json:"name"`
	AdapterVersion string `json:"adapter_version"`
	EngineVersion  string `json:"engine_version,omitempty"`
	RunID          string `json:"run_id,omitempty"`
}

// CanonicalFinding is Kelvin's unified vulnerability finding model adhering to finding.v1.json.
type CanonicalFinding struct {
	SchemaVersion     string         `json:"schema_version"`
	ID                string         `json:"id,omitempty"`
	Fingerprint       string         `json:"fingerprint,omitempty"`
	Status            string         `json:"status,omitempty"`
	Title             string         `json:"title"`
	Severity          string         `json:"severity"`
	Confidence        float64        `json:"confidence"`
	Target            Target         `json:"target"`
	Vulnerability     Vulnerability  `json:"vulnerability"`
	Description       string         `json:"description,omitempty"`
	ReproductionSteps []string       `json:"reproduction_steps,omitempty"`
	Remediation       *Remediation   `json:"remediation,omitempty"`
	Evidence          []Evidence     `json:"evidence,omitempty"`
	Scanner           ScannerInfo    `json:"scanner"`
	ScannerMeta       map[string]any `json:"scanner_meta,omitempty"`
	Tags              []string       `json:"tags,omitempty"`
	DiscoveredAt      string         `json:"discovered_at"`
}

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

	// Compute deterministic fingerprint
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
