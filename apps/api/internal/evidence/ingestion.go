// Package evidence provides evidence domain models, ingestion filters,
// association logic, and retention lifecycle management.
//
// See docs/architecture/EVIDENCE_INGESTION_AND_FINDING_ASSOCIATION.md.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

// Ingestion size bounds and error constants.
const (
	// MaxEvidenceSizeBytes represents the hard 1MB cap for ingested evidence payloads.
	MaxEvidenceSizeBytes = 1024 * 1024

	// MaxTruncatedExcerptLength defines maximum string length when truncating oversized text evidence.
	MaxTruncatedExcerptLength = 8192
)

var (
	// ErrEvidenceOversized is returned when an evidence item exceeds the 1MB ingestion threshold.
	ErrEvidenceOversized = errors.New("evidence: payload exceeds 1MB threshold")

	// ErrUnauthorizedSource is returned when an unauthenticated or untrusted caller attempts to inject evidence.
	ErrUnauthorizedSource = errors.New("evidence: unauthorized source attempted to attach verified evidence")

	// ErrTenantMismatch is returned when evidence scope violates tenant isolation boundaries.
	ErrTenantMismatch = errors.New("evidence: tenant boundary violation")

	// ErrMissingRequiredContext is returned when essential scoping identifiers are absent.
	ErrMissingRequiredContext = errors.New("evidence: missing required tenant, project, assessment, or job context")
)

// FindingEvidenceLink represents a relational junction associating an evidence item with a persistent finding.
type FindingEvidenceLink struct {
	ID            string    `json:"id" db:"id"`
	TenantID      string    `json:"tenant_id" db:"tenant_id"`
	FindingID     string    `json:"finding_id" db:"finding_id"`
	EvidenceID    string    `json:"evidence_id" db:"evidence_id"`
	ObservationID *string   `json:"observation_id,omitempty" db:"observation_id"`
	IsPrimary     bool      `json:"is_primary" db:"is_primary"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// Repository defines data access operations for persisting and querying evidence and links.
type Repository interface {
	SaveEvidence(ctx context.Context, item *EvidenceItem) error
	UpdateEvidence(ctx context.Context, item *EvidenceItem) error
	LinkFindingEvidence(ctx context.Context, link *FindingEvidenceLink) error
	GetEvidenceByID(ctx context.Context, tenantID, evidenceID string) (*EvidenceItem, error)
	GetEvidenceByFindingID(ctx context.Context, tenantID, findingID string) ([]*EvidenceItem, error)
	GetLinksByFindingID(ctx context.Context, tenantID, findingID string) ([]*FindingEvidenceLink, error)
	ListExpiredEvidence(ctx context.Context, before time.Time) ([]*EvidenceItem, error)
}

// IngestionService orchestrates intake, validation, redaction, and finding association of evidence.
type IngestionService struct {
	repo Repository
}

// NewIngestionService creates a new IngestionService.
func NewIngestionService(repo Repository) *IngestionService {
	return &IngestionService{
		repo: repo,
	}
}

// MapEvidenceType normalizes raw scanner evidence type strings to canonical EvidenceType enum.
func MapEvidenceType(rawType string) EvidenceType {
	normalized := strings.ToUpper(strings.TrimSpace(rawType))
	switch {
	case strings.Contains(normalized, "HEADER"):
		return TypeSecurityHeaderDiff
	case strings.Contains(normalized, "HTTP") || strings.Contains(normalized, "REQUEST") || strings.Contains(normalized, "RESPONSE"):
		return TypeHTTPObservation
	case strings.Contains(normalized, "TLS") || strings.Contains(normalized, "CERT"):
		return TypeTLSCertificate
	case strings.Contains(normalized, "SCREENSHOT") || strings.Contains(normalized, "IMAGE"):
		return TypeScreenshot
	case strings.Contains(normalized, "FILE") || strings.Contains(normalized, "ARTIFACT"):
		return TypeFileArtifact
	case strings.Contains(normalized, "SCANNER") || strings.Contains(normalized, "NUCLEI") || strings.Contains(normalized, "ZAP"):
		return TypeScannerExcerpt
	default:
		return TypeScannerExcerpt
	}
}

// IngestContext holds contextual scoping for ingesting finding evidence.
type IngestContext struct {
	TenantID          string
	ProjectID         string
	AssessmentID      string
	JobID             string
	FindingID         string
	ObservationID     string
	ScannerName       string
	IsTrustedWorkflow bool
}

// IngestFindingEvidence processes raw evidence items from Phase 2 canonical findings,
// enforces size limits, applies in-flight redactions, and records finding associations.
func (s *IngestionService) IngestFindingEvidence(
	ctx context.Context,
	ingestCtx IngestContext,
	rawEvidences []normalization.Evidence,
) ([]*EvidenceItem, error) {
	if ingestCtx.TenantID == "" || ingestCtx.ProjectID == "" || ingestCtx.AssessmentID == "" || ingestCtx.JobID == "" {
		return nil, ErrMissingRequiredContext
	}
	if !ingestCtx.IsTrustedWorkflow {
		return nil, ErrUnauthorizedSource
	}

	if _, err := uuid.Parse(ingestCtx.TenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id: %w", ErrMissingRequiredContext, err)
	}

	results := make([]*EvidenceItem, 0, len(rawEvidences))

	for i, raw := range rawEvidences {
		evType := MapEvidenceType(raw.Type)

		contentType := raw.ContentType
		if contentType == "" {
			contentType = "text/plain"
		}
		if !IsSafeMimeType(contentType) {
			contentType = "text/plain"
		}

		var payloadBytes []byte
		var storageRef string
		var isArtifact bool
		var size int64
		var checksum string

		if raw.Artifact != nil {
			isArtifact = true
			if raw.Artifact.ContentType != "" {
				contentType = raw.Artifact.ContentType
			}
			if raw.Artifact.SizeBytes > 0 {
				size = raw.Artifact.SizeBytes
			}
			if raw.Artifact.ChecksumSHA256 != "" {
				checksum = raw.Artifact.ChecksumSHA256
			}
			storageRef = fmt.Sprintf("artifacts/%s/%s/%s", ingestCtx.TenantID, ingestCtx.AssessmentID, raw.ID)
			if raw.Artifact.SizeBytes > MaxEvidenceSizeBytes {
				return nil, fmt.Errorf("%w: artifact exceeds %d bytes", ErrEvidenceOversized, MaxEvidenceSizeBytes)
			}
		} else {
			contentStr := raw.ContentRedacted
			if len(contentStr) > MaxEvidenceSizeBytes {
				return nil, fmt.Errorf("%w: raw content length %d exceeds maximum allowed %d",
					ErrEvidenceOversized, len(contentStr), MaxEvidenceSizeBytes)
			}
			payloadBytes = []byte(contentStr)
		}

		// Compute cryptographic checksum if not already determined
		if checksum == "" {
			if raw.ChecksumSHA256 != "" && len(raw.ChecksumSHA256) == 64 {
				checksum = raw.ChecksumSHA256
			} else if len(payloadBytes) > 0 {
				h := sha256.Sum256(payloadBytes)
				checksum = hex.EncodeToString(h[:])
			} else if storageRef != "" {
				h := sha256.Sum256([]byte(storageRef))
				checksum = hex.EncodeToString(h[:])
			} else {
				// Skip empty non-content evidence
				continue
			}
		}

		if size <= 0 {
			if raw.SizeBytes > 0 {
				size = raw.SizeBytes
			} else {
				size = int64(len(payloadBytes))
			}
		}

		redactionStatus := RedactionUnredactedInternal
		if len(raw.RedactedFields) > 0 || strings.Contains(string(payloadBytes), "[REDACTED]") {
			redactionStatus = RedactionSanitizedPresentation
		}

		now := time.Now().UTC()
		evidenceID := raw.ID
		if evidenceID == "" {
			evidenceID = uuid.New().String()
		}

		var findingIDPtr *string
		if ingestCtx.FindingID != "" {
			fid := ingestCtx.FindingID
			findingIDPtr = &fid
		}

		var obsIDPtr *string
		if ingestCtx.ObservationID != "" {
			oid := ingestCtx.ObservationID
			obsIDPtr = &oid
		}

		item := &EvidenceItem{
			ID:               evidenceID,
			TenantID:         ingestCtx.TenantID,
			ProjectID:        ingestCtx.ProjectID,
			AssessmentID:     ingestCtx.AssessmentID,
			JobID:            ingestCtx.JobID,
			FindingID:        findingIDPtr,
			ObservationID:    obsIDPtr,
			EvidenceType:     evType,
			Provenance:       ProvenanceCuratedFinding,
			ContentType:      contentType,
			StorageRef:       storageRef,
			ChecksumSHA256:   checksum,
			SizeBytes:        size,
			RedactionStatus:  redactionStatus,
			RedactedFields:   raw.RedactedFields,
			SensitivityLevel: SensitivityInternal,
			Status:           StatusActive,
			RetentionDays:    DefaultRetentionDays,
			ExpiresAt:        now.AddDate(0, 0, DefaultRetentionDays),
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		if !isArtifact && len(payloadBytes) <= MaxInlineSizeBytes {
			item.InlineContent = string(payloadBytes)
		} else if !isArtifact && storageRef == "" {
			item.StorageRef = fmt.Sprintf("evidence/%s/%s/%s", ingestCtx.TenantID, ingestCtx.AssessmentID, item.ID)
		}

		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("evidence validation failed: %w", err)
		}

		if err := s.repo.SaveEvidence(ctx, item); err != nil {
			return nil, fmt.Errorf("failed to save evidence: %w", err)
		}

		// Insert relational junction link if associated with a persistent finding
		if ingestCtx.FindingID != "" {
			link := &FindingEvidenceLink{
				ID:            uuid.New().String(),
				TenantID:      ingestCtx.TenantID,
				FindingID:     ingestCtx.FindingID,
				EvidenceID:    item.ID,
				ObservationID: obsIDPtr,
				IsPrimary:     i == 0, // First item is primary observation proof
				CreatedAt:     now,
			}
			if err := s.repo.LinkFindingEvidence(ctx, link); err != nil {
				return nil, fmt.Errorf("failed to link finding evidence: %w", err)
			}
		}

		results = append(results, item)
	}

	return results, nil
}

// MemoryRepository provides a concurrent-safe, in-memory implementation of Repository.
type MemoryRepository struct {
	mu       sync.RWMutex
	evidence map[string]*EvidenceItem
	links    map[string][]*FindingEvidenceLink
}

// NewMemoryRepository constructs a new MemoryRepository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		evidence: make(map[string]*EvidenceItem),
		links:    make(map[string][]*FindingEvidenceLink),
	}
}

// SaveEvidence stores an evidence item.
func (m *MemoryRepository) SaveEvidence(_ context.Context, item *EvidenceItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evidence[item.ID] = item
	return nil
}

// UpdateEvidence updates an existing evidence item in memory.
func (m *MemoryRepository) UpdateEvidence(_ context.Context, item *EvidenceItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evidence[item.ID] = item
	return nil
}

// ListExpiredEvidence returns evidence items whose expires_at is before the given timestamp.
func (m *MemoryRepository) ListExpiredEvidence(_ context.Context, before time.Time) ([]*EvidenceItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var expired []*EvidenceItem
	for _, item := range m.evidence {
		if item.ExpiresAt.Before(before) {
			expired = append(expired, item)
		}
	}
	return expired, nil
}

// LinkFindingEvidence links a finding to an evidence item.
func (m *MemoryRepository) LinkFindingEvidence(_ context.Context, link *FindingEvidenceLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := link.TenantID + ":" + link.FindingID
	m.links[key] = append(m.links[key], link)
	return nil
}

// GetEvidenceByID retrieves an evidence item by tenant and ID.
func (m *MemoryRepository) GetEvidenceByID(_ context.Context, tenantID, evidenceID string) (*EvidenceItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.evidence[evidenceID]
	if !ok {
		return nil, errors.New("evidence not found")
	}
	if item.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return item, nil
}

// GetEvidenceByFindingID retrieves all evidence items associated with a finding.
func (m *MemoryRepository) GetEvidenceByFindingID(_ context.Context, tenantID, findingID string) ([]*EvidenceItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := tenantID + ":" + findingID
	links := m.links[key]
	items := make([]*EvidenceItem, 0, len(links))
	for _, l := range links {
		if ev, ok := m.evidence[l.EvidenceID]; ok {
			items = append(items, ev)
		}
	}
	return items, nil
}

// GetLinksByFindingID retrieves all links associated with a finding.
func (m *MemoryRepository) GetLinksByFindingID(_ context.Context, tenantID, findingID string) ([]*FindingEvidenceLink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := tenantID + ":" + findingID
	return m.links[key], nil
}
