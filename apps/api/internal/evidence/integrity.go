// Package evidence provides cryptographic digest verification, scanner provenance
// tracking, tamper detection, and quarantined isolation for evidence items.
//
// See docs/architecture/EVIDENCE_INTEGRITY_AND_PROVENANCE_VERIFICATION.md.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Integrity algorithm and schema versions.
const (
	DigestAlgorithmSHA256 = "SHA-256"
	IntegrityVersion      = "kelvin.evidence_integrity.v1"
)

// Integrity status states.
const (
	IntegrityStatusVerified    = "VERIFIED"
	IntegrityStatusTampered    = "TAMPERED"
	IntegrityStatusMissing     = "MISSING"
	IntegrityStatusQuarantined = "QUARANTINED"
)

var (
	// ErrIntegrityMismatch is returned when the calculated SHA-256 digest differs from recorded checksum.
	ErrIntegrityMismatch = errors.New("evidence integrity check failed: digest mismatch detected")

	// ErrEvidenceQuarantined is returned when accessing an evidence object flagged as quarantined.
	ErrEvidenceQuarantined = errors.New("evidence is quarantined due to suspected tampering")
)

// ScannerProvenance preserves the complete chain of custody and execution context for evidence.
type ScannerProvenance struct {
	ScannerName    string    `json:"scanner_name"`
	EngineVersion  string    `json:"engine_version,omitempty"`
	AdapterVersion string    `json:"adapter_version,omitempty"`
	RunID          string    `json:"run_id,omitempty"`
	AssessmentID   string    `json:"assessment_id"`
	JobID          string    `json:"job_id"`
	CapturedAt     time.Time `json:"captured_at"`
}

// VerificationResult summarizes the outcome of an evidence integrity check.
type VerificationResult struct {
	EvidenceID       string            `json:"evidence_id"`
	TenantID         string            `json:"tenant_id"`
	Status           string            `json:"status"`
	ExpectedDigest   string            `json:"expected_digest"`
	CalculatedDigest string            `json:"calculated_digest"`
	Algorithm        string            `json:"algorithm"`
	Provenance       ScannerProvenance `json:"provenance"`
	VerifiedAt       time.Time         `json:"verified_at"`
	AlertTriggered   bool              `json:"alert_triggered"`
}

// IntegrityVerifier executes cryptographic validation and provenance tracking.
type IntegrityVerifier struct {
	logger *slog.Logger
}

// NewIntegrityVerifier constructs a new IntegrityVerifier.
func NewIntegrityVerifier(logger *slog.Logger) *IntegrityVerifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &IntegrityVerifier{
		logger: logger,
	}
}

// VerifyPayload computes the SHA-256 digest of payload and asserts equality against expectedDigest.
// On failure, it triggers an audit log alert without leaking sensitive payload bytes.
func (v *IntegrityVerifier) VerifyPayload(
	ctx context.Context,
	tenantID, evidenceID, expectedDigest string,
	payload []byte,
	provenance ScannerProvenance,
	verifierIdentity string,
) (*VerificationResult, error) {
	now := time.Now().UTC()

	hash := sha256.Sum256(payload)
	calculatedDigest := hex.EncodeToString(hash[:])

	res := &VerificationResult{
		EvidenceID:       evidenceID,
		TenantID:         tenantID,
		ExpectedDigest:   expectedDigest,
		CalculatedDigest: calculatedDigest,
		Algorithm:        DigestAlgorithmSHA256,
		Provenance:       provenance,
		VerifiedAt:       now,
	}

	if calculatedDigest != expectedDigest {
		res.Status = IntegrityStatusTampered
		res.AlertTriggered = true

		// Audit log: strictly logs metadata, NEVER prints sensitive payload
		v.logger.ErrorContext(ctx, "EVIDENCE_TAMPER_ALERT: integrity digest mismatch detected",
			"tenant_id", tenantID,
			"evidence_id", evidenceID,
			"expected_digest", expectedDigest,
			"calculated_digest", calculatedDigest,
			"verifier", verifierIdentity,
			"scanner", provenance.ScannerName,
		)

		return res, fmt.Errorf("%w: expected %s, got %s", ErrIntegrityMismatch, expectedDigest, calculatedDigest)
	}

	res.Status = IntegrityStatusVerified
	return res, nil
}

// VerifyItem inspects an EvidenceItem, computing SHA-256 over its inline content or storage object.
func (v *IntegrityVerifier) VerifyItem(
	ctx context.Context,
	item *EvidenceItem,
	storage StorageService,
	verifierIdentity string,
) (*VerificationResult, error) {
	if item.Status == StatusPurging || item.Status == StatusPurged {
		return nil, ErrEvidenceQuarantined
	}

	provenance := ScannerProvenance{
		AssessmentID: item.AssessmentID,
		JobID:        item.JobID,
		CapturedAt:   item.CreatedAt,
	}

	var data []byte

	if item.InlineContent != "" {
		data = []byte(item.InlineContent)
	} else if item.StorageRef != "" && storage != nil {
		var err error
		data, _, err = storage.GetObject(ctx, item.TenantID, item.ID)
		if err != nil {
			if errors.Is(err, ErrObjectNotFound) {
				return &VerificationResult{
					EvidenceID:     item.ID,
					TenantID:       item.TenantID,
					Status:         IntegrityStatusMissing,
					ExpectedDigest: item.ChecksumSHA256,
					Algorithm:      DigestAlgorithmSHA256,
					Provenance:     provenance,
					VerifiedAt:     time.Now().UTC(),
					AlertTriggered: true,
				}, fmt.Errorf("evidence binary missing in storage: %w", err)
			}
			return nil, err
		}
	} else {
		return nil, errors.New("cannot verify evidence without inline content or storage adapter")
	}

	return v.VerifyPayload(ctx, item.TenantID, item.ID, item.ChecksumSHA256, data, provenance, verifierIdentity)
}
