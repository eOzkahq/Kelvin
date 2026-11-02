// Package evidence defines the core domain model, metadata schemas,
// sensitivity classifications, and lifecycle rules for evidence management.
//
// See docs/architecture/EVIDENCE_MANAGEMENT_DOMAIN_LIFECYCLE.md and
// docs/security/DATA_LIFECYCLE.md for normative specifications.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EvidenceType enumerates supported forms of proof captured during scans.
type EvidenceType string

const (
	TypeHTTPObservation      EvidenceType = "HTTP_EXCERPT"
	TypeSecurityHeaderDiff   EvidenceType = "SECURITY_HEADER_DIFF"
	TypeTLSCertificate       EvidenceType = "TLS_CERTIFICATE"
	TypeScannerExcerpt       EvidenceType = "SCANNER_EXCERPT"
	TypeScreenshot           EvidenceType = "SCREENSHOT"
	TypeFileArtifact         EvidenceType = "FILE_ARTIFACT"
)

// Valid returns true if the EvidenceType is supported.
func (t EvidenceType) Valid() bool {
	switch t {
	case TypeHTTPObservation,
		TypeSecurityHeaderDiff,
		TypeTLSCertificate,
		TypeScannerExcerpt,
		TypeScreenshot,
		TypeFileArtifact:
		return true
	default:
		return false
	}
}

// EvidenceProvenance classifies whether the evidence is raw scanner output
// or curated/synthesized finding evidence.
type EvidenceProvenance string

const (
	ProvenanceRawScanner     EvidenceProvenance = "RAW_SCANNER"
	ProvenanceCuratedFinding EvidenceProvenance = "CURATED_FINDING"
)

// Valid returns true if the Provenance is recognized.
func (p EvidenceProvenance) Valid() bool {
	return p == ProvenanceRawScanner || p == ProvenanceCuratedFinding
}

// SensitivityLevel classifies data handling, confidentiality, and access control boundaries.
type SensitivityLevel string

const (
	SensitivityPublic       SensitivityLevel = "PUBLIC"       // General public safe
	SensitivityInternal     SensitivityLevel = "INTERNAL"     // Default: tenant team members
	SensitivityConfidential SensitivityLevel = "CONFIDENTIAL" // Tenant security leads & auditors
	SensitivityRestricted   SensitivityLevel = "RESTRICTED"   // Sensitive secrets, strictly audited
)

// Valid returns true if the SensitivityLevel is recognized.
func (s SensitivityLevel) Valid() bool {
	switch s {
	case SensitivityPublic,
		SensitivityInternal,
		SensitivityConfidential,
		SensitivityRestricted:
		return true
	default:
		return false
	}
}

// RedactionStatus tracks whether credentials, auth headers, or tokens have been sanitized.
type RedactionStatus string

const (
	RedactionUnredactedInternal   RedactionStatus = "UNREDACTED_INTERNAL"
	RedactionSanitizedPresentation RedactionStatus = "SANITIZED_PRESENTATION"
)

// Valid returns true if the RedactionStatus is recognized.
func (r RedactionStatus) Valid() bool {
	return r == RedactionUnredactedInternal || r == RedactionSanitizedPresentation
}

// MaxInlineSizeBytes defines the threshold (64 KB) under which evidence
// is kept inline in the database rather than requiring object store storage.
const MaxInlineSizeBytes = 64 * 1024

// DefaultRetentionDays defines the default active retention duration (90 days).
const DefaultRetentionDays = 90

// EvidenceItem represents an immutable piece of technical proof captured during an assessment.
type EvidenceItem struct {
	ID                string             `json:"id" db:"id"`
	TenantID          string             `json:"tenant_id" db:"tenant_id"`
	ProjectID         string             `json:"project_id" db:"project_id"`
	AssessmentID      string             `json:"assessment_id" db:"assessment_id"`
	JobID             string             `json:"job_id" db:"job_id"`
	FindingID         *string            `json:"finding_id,omitempty" db:"finding_id"`
	ObservationID     *string            `json:"observation_id,omitempty" db:"observation_id"`
	EvidenceType      EvidenceType       `json:"evidence_type" db:"evidence_type"`
	Provenance        EvidenceProvenance `json:"provenance" db:"provenance"`
	ContentType       string             `json:"content_type" db:"content_type"`
	StorageRef        string             `json:"storage_ref,omitempty" db:"storage_ref"`
	InlineContent     string             `json:"inline_content,omitempty" db:"inline_content"`
	ChecksumSHA256    string             `json:"checksum_sha256" db:"checksum_sha256"`
	SizeBytes         int64              `json:"size_bytes" db:"size_bytes"`
	RedactionStatus   RedactionStatus    `json:"redaction_status" db:"redaction_status"`
	RedactedFields    []string           `json:"redacted_fields" db:"redacted_fields"`
	SensitivityLevel  SensitivityLevel   `json:"sensitivity_level" db:"sensitivity_level"`
	Status            EvidenceStatus     `json:"status" db:"status"`
	RetentionDays     int                `json:"retention_days" db:"retention_days"`
	ExpiresAt         time.Time          `json:"expires_at" db:"expires_at"`
	IsLegalHold       bool               `json:"is_legal_hold" db:"is_legal_hold"`
	LegalHoldReason   string             `json:"legal_hold_reason,omitempty" db:"legal_hold_reason"`
	WipedAt           *time.Time         `json:"wiped_at,omitempty" db:"wiped_at"`
	PurgeRetryCount   int                `json:"purge_retry_count" db:"purge_retry_count"`
	CreatedAt         time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at" db:"updated_at"`
}

// Validate validates that the evidence item satisfies domain invariants and boundaries.
func (e *EvidenceItem) Validate() error {
	if _, err := uuid.Parse(e.TenantID); err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}
	if _, err := uuid.Parse(e.ProjectID); err != nil {
		return fmt.Errorf("invalid project_id: %w", err)
	}
	if _, err := uuid.Parse(e.AssessmentID); err != nil {
		return fmt.Errorf("invalid assessment_id: %w", err)
	}
	if _, err := uuid.Parse(e.JobID); err != nil {
		return fmt.Errorf("invalid job_id: %w", err)
	}
	if e.FindingID != nil && *e.FindingID != "" {
		if _, err := uuid.Parse(*e.FindingID); err != nil {
			return fmt.Errorf("invalid finding_id: %w", err)
		}
	}
	if e.ObservationID != nil && *e.ObservationID != "" {
		if _, err := uuid.Parse(*e.ObservationID); err != nil {
			return fmt.Errorf("invalid observation_id: %w", err)
		}
	}

	if !e.EvidenceType.Valid() {
		return fmt.Errorf("invalid evidence_type: %q", e.EvidenceType)
	}
	if !e.Provenance.Valid() {
		return fmt.Errorf("invalid provenance: %q", e.Provenance)
	}
	if !e.SensitivityLevel.Valid() {
		return fmt.Errorf("invalid sensitivity_level: %q", e.SensitivityLevel)
	}
	if !e.RedactionStatus.Valid() {
		return fmt.Errorf("invalid redaction_status: %q", e.RedactionStatus)
	}

	if !IsSafeMimeType(e.ContentType) {
		return fmt.Errorf("disallowed or executable content_type: %q", e.ContentType)
	}

	if e.SizeBytes < 0 {
		return errors.New("size_bytes must not be negative")
	}

	if len(e.ChecksumSHA256) != 64 {
		return errors.New("checksum_sha256 must be a 64-character hex string")
	}

	if e.Status != StatusPurged && e.InlineContent == "" && e.StorageRef == "" {
		return errors.New("either inline_content or storage_ref must be provided")
	}

	if len(e.InlineContent) > MaxInlineSizeBytes {
		return fmt.Errorf("inline_content exceeds maximum threshold of %d bytes", MaxInlineSizeBytes)
	}

	return nil
}

// DisallowedMimeTypes contains executable or active payload types rejected
// to enforce the invariant that evidence is untrusted data.
var DisallowedMimeTypes = map[string]struct{}{
	"application/x-msdownload":      {},
	"application/x-executable":      {},
	"application/x-dosexec":         {},
	"application/x-sharedlib":       {},
	"application/x-shellscript":     {},
	"application/x-sh":              {},
	"application/x-bat":             {},
	"application/vnd.microsoft.portable-executable": {},
}

// IsSafeMimeType returns true if the content type is permitted for evidence storage.
func IsSafeMimeType(contentType string) bool {
	base := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if base == "" {
		return false
	}
	_, disallowed := DisallowedMimeTypes[base]
	return !disallowed
}

// SensitiveHeaderKeys are header names whose values must be sanitized before presentation.
var SensitiveHeaderKeys = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"private-token":       {},
	"session-token":       {},
}

// SanitizeHeaderValue inspects a header key/value pair and masks it if sensitive.
// Returns the sanitized value and true if redaction occurred.
func SanitizeHeaderValue(key, val string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(key))
	if _, ok := SensitiveHeaderKeys[lower]; ok {
		if len(val) <= 8 {
			return "[REDACTED]", true
		}
		// Preserve minimal prefix for debugging while concealing secret
		return val[:4] + "...[REDACTED]", true
	}
	return val, false
}

// SanitizeHeaders creates a copy of the headers with sensitive values masked.
func SanitizeHeaders(headers map[string][]string) (map[string][]string, []string) {
	sanitized := make(map[string][]string, len(headers))
	var redactedKeys []string

	for k, vals := range headers {
		sanVals := make([]string, len(vals))
		keyRedacted := false
		for i, v := range vals {
			masked, wasRedacted := SanitizeHeaderValue(k, v)
			sanVals[i] = masked
			if wasRedacted {
				keyRedacted = true
			}
		}
		sanitized[k] = sanVals
		if keyRedacted {
			redactedKeys = append(redactedKeys, k)
		}
	}

	return sanitized, redactedKeys
}

// NewEvidenceItem constructs and initializes a validated EvidenceItem.
func NewEvidenceItem(
	tenantID, projectID, assessmentID, jobID string,
	evType EvidenceType,
	provenance EvidenceProvenance,
	contentType string,
	content []byte,
) (*EvidenceItem, error) {
	now := time.Now().UTC()
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])
	size := int64(len(content))

	item := &EvidenceItem{
		ID:               uuid.New().String(),
		TenantID:         tenantID,
		ProjectID:        projectID,
		AssessmentID:     assessmentID,
		JobID:            jobID,
		EvidenceType:     evType,
		Provenance:       provenance,
		ContentType:      contentType,
		ChecksumSHA256:   checksum,
		SizeBytes:        size,
		RedactionStatus:  RedactionUnredactedInternal,
		RedactedFields:   []string{},
		SensitivityLevel: SensitivityInternal,
		Status:           StatusActive,
		RetentionDays:    DefaultRetentionDays,
		ExpiresAt:        now.AddDate(0, 0, DefaultRetentionDays),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if size <= MaxInlineSizeBytes {
		item.InlineContent = string(content)
	}

	if err := item.Validate(); err != nil {
		return nil, err
	}

	return item, nil
}
