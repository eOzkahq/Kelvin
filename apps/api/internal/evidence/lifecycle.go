// Package evidence implements evidence lifecycle management: signed URL
// generation and validation, retention sweeps, and cascading deletion of
// evidence records and their object-store binaries.
//
// See docs/security/DATA_LIFECYCLE.md for the normative architecture.
package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultSignedURLTTL is the default lifetime for signed evidence download URLs.
const defaultSignedURLTTL = 15 * time.Minute

// maxSignedURLTTL is the maximum allowed lifetime for signed URLs.
const maxSignedURLTTL = 24 * time.Hour

// signingKeySize is the size in bytes of the HMAC signing key.
const signingKeySize = 32

// ErrExpired is returned when a signed URL has expired.
var ErrExpired = errors.New("evidence: signed URL has expired")

// ErrInvalidSignature is returned when a signed URL signature does not match.
var ErrInvalidSignature = errors.New("evidence: invalid signature")

// ErrMalformedURL is returned when a signed URL cannot be parsed.
var ErrMalformedURL = errors.New("evidence: malformed signed URL")

// EvidenceStatus is the lifecycle status of an evidence record.
type EvidenceStatus string

const (
	StatusActive      EvidenceStatus = "active"       // Active, signed URLs available
	StatusArchived    EvidenceStatus = "archived"     // Moved to cold storage, short TTL URLs
	StatusPurging     EvidenceStatus = "purging"      // Secure erasure in progress
	StatusPurged      EvidenceStatus = "purged"       // Securely erased
	StatusPurgeFailed EvidenceStatus = "purge_failed" // Erasure failed, retry scheduled
)

// Record is a stored evidence record.
type Record struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	AssessmentID string         `json:"assessment_id"`
	FindingID    string         `json:"finding_id,omitempty"`
	ObjectKey    string         `json:"object_key"` // Object store key
	ContentType  string         `json:"content_type"`
	SizeBytes    int64          `json:"size_bytes"`
	SHA256       string         `json:"sha256"` // SHA-256 of original content
	Status       EvidenceStatus `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"` // Archive/purge timestamp
	DeletedAt    *time.Time     `json:"deleted_at,omitempty"` // Soft delete timestamp
}

// Signer generates and validates HMAC-SHA256 signed URLs for evidence download.
type Signer struct {
	key []byte
}

// NewSigner creates a Signer with the given HMAC key (must be >= 32 bytes).
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < signingKeySize {
		return nil, errors.New("evidence: signing key must be at least 32 bytes")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k}, nil
}

// SignDownloadURL generates a signed download URL for an evidence record.
// The URL includes expires and signature query parameters.
func (s *Signer) SignDownloadURL(evidenceID, tenantID string, ttl time.Duration, baseURL string) (string, error) {
	if ttl <= 0 {
		ttl = defaultSignedURLTTL
	}
	if ttl > maxSignedURLTTL {
		ttl = maxSignedURLTTL
	}
	expires := time.Now().UTC().Add(ttl).Unix()

	message := fmt.Sprintf("%s|%s|%d", evidenceID, tenantID, expires)
	sig := hmac.New(sha256.New, s.key)
	sig.Write([]byte(message))
	signature := hex.EncodeToString(sig.Sum(nil))

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("evidence: parse base URL: %w", err)
	}
	q := u.Query()
	q.Set("expires", strconv.FormatInt(expires, 10))
	q.Set("signature", signature)
	q.Set("tenant_id", tenantID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ValidateDownloadURL validates a signed download URL and returns the
// evidence ID, tenant ID, and expiry if valid.
func (s *Signer) ValidateDownloadURL(rawURL string) (evidenceID, tenantID string, expires int64, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", 0, ErrMalformedURL
	}
	q := u.Query()
	signature := q.Get("signature")
	expiresStr := q.Get("expires")
	if signature == "" || expiresStr == "" {
		return "", "", 0, ErrMalformedURL
	}
	expiresInt, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return "", "", 0, ErrMalformedURL
	}
	if time.Unix(expiresInt, 0).UTC().Before(time.Now().UTC()) {
		return "", "", 0, ErrExpired
	}

	// Reconstruct the message from the path and query params.
	// Path: /api/v1/evidence/{evidence_id}/download
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "evidence" || parts[3] == "" {
		return "", "", 0, ErrMalformedURL
	}
	evidenceID = parts[3]
	tenantID = q.Get("tenant_id")
	if tenantID == "" {
		return "", "", 0, ErrMalformedURL
	}

	message := fmt.Sprintf("%s|%s|%d", evidenceID, tenantID, expiresInt)
	expected := hmac.New(sha256.New, s.key)
	expected.Write([]byte(message))
	expectedSig := hex.EncodeToString(expected.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", 0, ErrInvalidSignature
	}
	return evidenceID, tenantID, expiresInt, nil
}

// Store is the persistence interface for evidence records. Implementations
// must be safe for concurrent use.
type Store interface {
	// Get returns the evidence record by ID.
	Get(id string) (*Record, error)
	// GetByTenant returns evidence records for a tenant, optionally filtered
	// by status and created-before timestamp.
	GetByTenant(tenantID string, status EvidenceStatus, before *time.Time) ([]*Record, error)
	// UpdateStatus transitions a record to a new status.
	UpdateStatus(id string, status EvidenceStatus) error
	// SoftDelete marks a record as deleted (deleted_at set).
	SoftDelete(id string) error
	// HardDelete permanently removes a record.
	HardDelete(id string) error
}

// ObjectStore is the object storage interface for evidence binaries.
type ObjectStore interface {
	// Delete removes an object by key.
	Delete(key string) error
	// OverwriteWithRandom overwrites an object with cryptographically random
	// data of the same length as the original, then deletes it.
	OverwriteWithRandom(key string, size int64) error
}

// RetentionPolicy defines retention periods for evidence.
type RetentionPolicy struct {
	// ActiveDays is the number of days evidence remains active with full TTL
	// signed URLs.
	ActiveDays int `mapstructure:"active_days"`
	// ArchivedDays is the number of days evidence remains in archived state
	// before purge.
	ArchivedDays int `mapstructure:"archived_days"`
	// PurgeGraceDays is the grace period after soft-delete before hard-delete.
	PurgeGraceDays int `mapstructure:"purge_grace_days"`
}

// DefaultRetentionPolicy returns the default retention policy from
// DATA_LIFECYCLE.md §3.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		ActiveDays:     90,
		ArchivedDays:   270,
		PurgeGraceDays: 7,
	}
}

// SweepResult summarizes the outcome of a retention sweep.
type SweepResult struct {
	Scanned  int `json:"scanned"`
	Archived int `json:"archived"`
	Purged   int `json:"purged"`
	Failed   int `json:"failed"`
}

// Sweeper performs retention sweeps: archives expired active records and
// securely purges expired archived records.
type Sweeper struct {
	store   Store
	objects ObjectStore
	policy  RetentionPolicy
}

// NewSweeper creates a Sweeper.
func NewSweeper(store Store, objects ObjectStore, policy RetentionPolicy) *Sweeper {
	return &Sweeper{store: store, objects: objects, policy: policy}
}

// Sweep performs one retention sweep cycle. It archives records whose active
// period has expired and purges records whose archive period has expired.
//
// Returns a SweepResult summarizing the outcome.
func (s *Sweeper) Sweep() (SweepResult, error) {
	result := SweepResult{}

	now := time.Now().UTC()

	// Archive active records whose active period has expired.
	archiveBefore := now.Add(-time.Duration(s.policy.ActiveDays) * 24 * time.Hour)
	activeRecords, err := s.store.GetByTenant("", StatusActive, &archiveBefore)
	if err != nil {
		return result, fmt.Errorf("evidence: fetch active records: %w", err)
	}
	result.Scanned += len(activeRecords)
	for _, rec := range activeRecords {
		if err := s.store.UpdateStatus(rec.ID, StatusArchived); err != nil {
			result.Failed++
			continue
		}
		result.Archived++
	}

	// Purge archived records whose archive period has expired.
	purgeBefore := now.Add(-time.Duration(s.policy.ActiveDays+s.policy.ArchivedDays) * 24 * time.Hour)
	archivedRecords, err := s.store.GetByTenant("", StatusArchived, &purgeBefore)
	if err != nil {
		return result, fmt.Errorf("evidence: fetch archived records: %w", err)
	}
	result.Scanned += len(archivedRecords)
	for _, rec := range archivedRecords {
		// Securely erase the object store binary.
		if err := s.objects.OverwriteWithRandom(rec.ObjectKey, rec.SizeBytes); err != nil {
			// Mark as purge_failed for retry.
			_ = s.store.UpdateStatus(rec.ID, StatusPurgeFailed)
			result.Failed++
			continue
		}
		// Delete the object.
		if err := s.objects.Delete(rec.ObjectKey); err != nil {
			_ = s.store.UpdateStatus(rec.ID, StatusPurgeFailed)
			result.Failed++
			continue
		}
		// Soft-delete the database record.
		if err := s.store.SoftDelete(rec.ID); err != nil {
			result.Failed++
			continue
		}
		result.Purged++
	}

	return result, nil
}
