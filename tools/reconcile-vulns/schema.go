package main

import "time"

// WaiverRegistry represents the canonical YAML structure (ADR-0008).
type WaiverRegistry struct {
	SchemaVersion string         `yaml:"schema_version"`
	Scanner       string         `yaml:"scanner"`
	Metadata      WaiverMetadata `yaml:"metadata"`
	Waivers       []WaiverEntry  `yaml:"waivers"`
}

type WaiverMetadata struct {
	PolicyReference   string         `yaml:"policy_reference"`
	Description       string         `yaml:"description"`
	UpdatedAt         string         `yaml:"updated_at"`
	TTLDays           map[string]int `yaml:"ttl_days"`
	ExpiryWarningDays int            `yaml:"expiry_warning_days"`
}

type WaiverEntry struct {
	CVEID                  string          `yaml:"cve_id"`
	Component              string          `yaml:"component"`
	Severity               string          `yaml:"severity"`
	TechnicalJustification string          `yaml:"technical_justification"`
	Status                 string          `yaml:"status"` // pending_review, approved, expired, rejected
	Owner                  *string         `yaml:"owner"`
	ReviewDate             *string         `yaml:"review_date"`
	ExpiryDate             *string         `yaml:"expiry_date"`
	TrackingReference      string          `yaml:"tracking_reference"`
	Approval               *WaiverApproval `yaml:"approval"`
}

type WaiverApproval struct {
	Approver   string `yaml:"approver"`
	ApprovedAt string `yaml:"approved_at"`
	Signature  string `yaml:"signature,omitempty"`
}

// CycloneDXSBOM represents vulnerability findings in CycloneDX v1.4/v1.5 format.
type CycloneDXSBOM struct {
	BOMFormat       string           `json:"bomFormat"`
	SpecVersion     string           `json:"specVersion"`
	Vulnerabilities []SBOMVulnRecord `json:"vulnerabilities"`
}

type SBOMVulnRecord struct {
	ID          string               `json:"id"`
	Ratings     []SBOMRating         `json:"ratings,omitempty"`
	Description string               `json:"description,omitempty"`
	Affects     []SBOMAffectsPackage `json:"affects,omitempty"`
}

type SBOMRating struct {
	Severity string  `json:"severity"`
	Score    float64 `json:"score,omitempty"`
}

type SBOMAffectsPackage struct {
	Ref string `json:"ref"` // package URL or reference
}

// ReconciliationReport is the deterministic output of the reconciliation engine.
type ReconciliationReport struct {
	SchemaVersion          string                `json:"schema_version"`
	AuditDate              string                `json:"audit_date"`
	Scanner                string                `json:"scanner"`
	TotalRawFindings       int                   `json:"total_raw_findings"`
	TotalRegisteredWaivers int                   `json:"total_registered_waivers"`
	Summary                ReconciliationSummary `json:"summary"`
	Verdict                string                `json:"verdict"` // PASS or GATED
	Findings               []ReconciledFinding   `json:"findings"`
}

type ReconciliationSummary struct {
	Fixed     int `json:"fixed"`     // Registered waiver but no longer present in raw scan
	Approved  int `json:"approved"`  // Present and covered by active approved waiver
	Pending   int `json:"pending"`   // Present but covered only by pending_review waiver
	Expired   int `json:"expired"`   // Present but matching waiver is expired
	Unhandled int `json:"unhandled"` // Present in raw scan with no waiver at all
}

type ReconciledFinding struct {
	CVEID       string `json:"cve_id"`
	Component   string `json:"component"`
	Severity    string `json:"severity"`
	Disposition string `json:"disposition"` // fixed, approved, pending, expired, unhandled
	Reason      string `json:"reason"`
	ExpiryDate  string `json:"expiry_date,omitempty"`
}

// Classification represents internal disposition constants.
const (
	DispositionFixed     = "fixed"
	DispositionApproved  = "approved"
	DispositionPending   = "pending"
	DispositionExpired   = "expired"
	DispositionUnhandled = "unhandled"

	VerdictPass  = "PASS"
	VerdictGated = "GATED"
)

// DateFormat standard for ISO 8601 day strings.
const DateFormat = "2006-01-02"

func parseDate(s string) (time.Time, error) {
	return time.Parse(DateFormat, s)
}
