package normalization

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

