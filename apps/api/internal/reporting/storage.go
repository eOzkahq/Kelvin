package reporting

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrReportRevoked     = errors.New("reporting: report artifact has been revoked")
	ErrReportExpired     = errors.New("reporting: report artifact has expired")
	ErrInvalidToken      = errors.New("reporting: invalid or expired download token")
	ErrArtifactNotFound  = errors.New("reporting: report artifact not found")
	ErrUnsupportedFormat = errors.New("reporting: unsupported report format")
)

// ReportFormat specifies the export rendering format.
type ReportFormat string

const (
	FormatHTML ReportFormat = "HTML"
	FormatPDF  ReportFormat = "PDF"
)

func (f ReportFormat) IsValid() bool {
	return f == FormatHTML || f == FormatPDF
}

// ReportArtifactRecord tracks an encrypted, stored report deliverable.
type ReportArtifactRecord struct {
	ID               uuid.UUID    `json:"id"`
	TenantID         uuid.UUID    `json:"tenant_id"`
	ReportID         uuid.UUID    `json:"report_id"`
	AssessmentID     uuid.UUID    `json:"assessment_id"`
	Format           ReportFormat `json:"format"`
	StoragePath      string       `json:"storage_path"`
	SHA256Checksum   string       `json:"sha256_checksum"`
	SizeBytes        int64        `json:"size_bytes"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty"`
	IsRevoked        bool         `json:"is_revoked"`
	RevocationReason string       `json:"revocation_reason,omitempty"`
	RevokedAt        *time.Time   `json:"revoked_at,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
}

// ObjectStore manages encrypted blob persistence for report documents.
type ObjectStore interface {
	Put(ctx context.Context, path string, data []byte) error
	Get(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
}

// MemoryObjectStore provides thread-safe in-memory blob storage.
type MemoryObjectStore struct {
	mu    sync.RWMutex
	blobs map[string][]byte
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{blobs: make(map[string][]byte)}
}

func (m *MemoryObjectStore) Put(_ context.Context, path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]byte, len(data))
	copy(copied, data)
	m.blobs[path] = copied
	return nil
}

func (m *MemoryObjectStore) Get(_ context.Context, path string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, exists := m.blobs[path]
	if !exists {
		return nil, errors.New("blob not found")
	}
	copied := make([]byte, len(b))
	copy(copied, b)
	return copied, nil
}

func (m *MemoryObjectStore) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs, path)
	return nil
}

// ArtifactRepository defines database interactions for report artifacts.
type ArtifactRepository interface {
	SaveArtifact(ctx context.Context, artifact *ReportArtifactRecord) error
	GetArtifact(ctx context.Context, tenantID, reportID uuid.UUID, format ReportFormat) (*ReportArtifactRecord, error)
	RevokeArtifacts(ctx context.Context, tenantID, reportID uuid.UUID, reason string) error
}

// MemoryArtifactRepository provides thread-safe repository storage for artifacts.
type MemoryArtifactRepository struct {
	mu        sync.RWMutex
	artifacts map[string]ReportArtifactRecord // key: tenantID:reportID:format
}

func NewMemoryArtifactRepository() *MemoryArtifactRepository {
	return &MemoryArtifactRepository{
		artifacts: make(map[string]ReportArtifactRecord),
	}
}

func makeArtifactKey(tenantID, reportID uuid.UUID, format ReportFormat) string {
	return fmt.Sprintf("%s:%s:%s", tenantID, reportID, format)
}

func (m *MemoryArtifactRepository) SaveArtifact(_ context.Context, artifact *ReportArtifactRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeArtifactKey(artifact.TenantID, artifact.ReportID, artifact.Format)
	m.artifacts[key] = *artifact
	return nil
}

func (m *MemoryArtifactRepository) GetArtifact(_ context.Context, tenantID, reportID uuid.UUID, format ReportFormat) (*ReportArtifactRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := makeArtifactKey(tenantID, reportID, format)
	a, exists := m.artifacts[key]
	if !exists {
		return nil, ErrArtifactNotFound
	}
	if a.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	copied := a
	return &copied, nil
}

func (m *MemoryArtifactRepository) RevokeArtifacts(_ context.Context, tenantID, reportID uuid.UUID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	found := false
	for k, a := range m.artifacts {
		if a.TenantID == tenantID && a.ReportID == reportID {
			a.IsRevoked = true
			a.RevocationReason = reason
			a.RevokedAt = &now
			m.artifacts[k] = a
			found = true
		}
	}
	if !found {
		return ErrArtifactNotFound
	}
	return nil
}

// ReportURLSigner generates and validates ephemeral HMAC-SHA256 download links.
type ReportURLSigner struct {
	secret []byte
}

func NewReportURLSigner(secret []byte) *ReportURLSigner {
	return &ReportURLSigner{secret: secret}
}

func (s *ReportURLSigner) GenerateToken(tenantID, reportID uuid.UUID, format ReportFormat, expiresUnix int64) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(fmt.Sprintf("%s:%s:%s:%d", tenantID, reportID, format, expiresUnix)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *ReportURLSigner) ValidateToken(token string, tenantID, reportID uuid.UUID, format ReportFormat, expiresUnix int64) error {
	if time.Now().UTC().Unix() > expiresUnix {
		return ErrInvalidToken
	}
	expected := s.GenerateToken(tenantID, reportID, format, expiresUnix)
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return ErrInvalidToken
	}
	return nil
}

// SecureReportService manages the storage, tokenized delivery, and revocation of report artifacts.
type SecureReportService struct {
	artifactRepo ArtifactRepository
	objectStore  ObjectStore
	snapshotRepo SnapshotRepository
	signer       *ReportURLSigner
}

func NewSecureReportService(
	artifactRepo ArtifactRepository,
	objectStore ObjectStore,
	snapshotRepo SnapshotRepository,
	signer *ReportURLSigner,
) *SecureReportService {
	return &SecureReportService{
		artifactRepo: artifactRepo,
		objectStore:  objectStore,
		snapshotRepo: snapshotRepo,
		signer:       signer,
	}
}

// StoreReportArtifact saves rendered report bytes to secure storage and registers artifact metadata.
func (s *SecureReportService) StoreReportArtifact(
	ctx context.Context,
	tenantID, reportID, assessmentID uuid.UUID,
	format ReportFormat,
	content []byte,
	ttl *time.Duration,
) (*ReportArtifactRecord, error) {
	if tenantID == uuid.Nil {
		return nil, ErrInvalidTenantID
	}
	if reportID == uuid.Nil {
		return nil, ErrInvalidReportID
	}
	if !format.IsValid() {
		return nil, ErrUnsupportedFormat
	}
	if len(content) == 0 {
		return nil, errors.New("cannot store empty report content")
	}

	// Compute SHA-256 integrity checksum
	h := sha256.Sum256(content)
	checksum := hex.EncodeToString(h[:])

	// Secure tenant-isolated storage path
	storagePath := fmt.Sprintf("reports/%s/%s/report.%s", tenantID, reportID, strings.ToLower(string(format)))

	if err := s.objectStore.Put(ctx, storagePath, content); err != nil {
		return nil, fmt.Errorf("failed to store artifact blob: %w", err)
	}

	var expiresAt *time.Time
	if ttl != nil {
		t := time.Now().UTC().Add(*ttl)
		expiresAt = &t
	}

	now := time.Now().UTC()
	artifact := &ReportArtifactRecord{
		ID:             uuid.New(),
		TenantID:       tenantID,
		ReportID:       reportID,
		AssessmentID:   assessmentID,
		Format:         format,
		StoragePath:    storagePath,
		SHA256Checksum: checksum,
		SizeBytes:      int64(len(content)),
		ExpiresAt:      expiresAt,
		IsRevoked:      false,
		CreatedAt:      now,
	}

	if err := s.artifactRepo.SaveArtifact(ctx, artifact); err != nil {
		return nil, fmt.Errorf("failed to register artifact: %w", err)
	}

	return artifact, nil
}

// GetReportDownloadURL generates an ephemeral, pre-signed download URL for a report artifact.
func (s *SecureReportService) GetReportDownloadURL(
	ctx context.Context,
	baseURL string,
	tenantID, reportID uuid.UUID,
	format ReportFormat,
	linkTTL time.Duration,
	_ string, // actorID recorded for audit
) (string, error) {
	artifact, err := s.artifactRepo.GetArtifact(ctx, tenantID, reportID, format)
	if err != nil {
		return "", err
	}

	if artifact.IsRevoked {
		return "", ErrReportRevoked
	}
	if artifact.ExpiresAt != nil && artifact.ExpiresAt.Before(time.Now().UTC()) {
		return "", ErrReportExpired
	}

	if linkTTL <= 0 {
		linkTTL = 300 * time.Second // default 5 minutes
	}
	expiresUnix := time.Now().UTC().Add(linkTTL).Unix()
	token := s.signer.GenerateToken(tenantID, reportID, format, expiresUnix)

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}

	q := parsedBase.Query()
	q.Set("token", token)
	q.Set("expires", strconv.FormatInt(expiresUnix, 10))
	q.Set("format", string(format))
	parsedBase.RawQuery = q.Encode()

	return parsedBase.String(), nil
}

// DownloadReportContent verifies the ephemeral token and retrieves report bytes.
func (s *SecureReportService) DownloadReportContent(
	ctx context.Context,
	tenantID, reportID uuid.UUID,
	format ReportFormat,
	token string,
	expiresUnix int64,
	_ string, // actorID for audit
) ([]byte, *ReportArtifactRecord, error) {
	// 1. Verify ephemeral signed token
	if err := s.signer.ValidateToken(token, tenantID, reportID, format, expiresUnix); err != nil {
		return nil, nil, err
	}

	// 2. Retrieve artifact record
	artifact, err := s.artifactRepo.GetArtifact(ctx, tenantID, reportID, format)
	if err != nil {
		return nil, nil, err
	}

	// 3. Verify revocation status
	if artifact.IsRevoked {
		return nil, nil, ErrReportRevoked
	}

	// 4. Verify artifact retention expiration
	if artifact.ExpiresAt != nil && artifact.ExpiresAt.Before(time.Now().UTC()) {
		return nil, nil, ErrReportExpired
	}

	// 5. Retrieve object bytes from store
	data, err := s.objectStore.Get(ctx, artifact.StoragePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve report content: %w", err)
	}

	// 6. Verify integrity checksum on download
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != artifact.SHA256Checksum {
		return nil, nil, errors.New("reporting: artifact checksum mismatch on download")
	}

	return data, artifact, nil
}

// RevokeReport revokes all artifacts associated with a report ID.
func (s *SecureReportService) RevokeReport(
	ctx context.Context,
	tenantID, reportID uuid.UUID,
	reason string,
	_ string, // actorID for audit
) error {
	if reason == "" {
		return errors.New("reporting: revocation reason is required")
	}
	return s.artifactRepo.RevokeArtifacts(ctx, tenantID, reportID, reason)
}

// RegenerateArtifact re-renders an artifact from its immutable snapshot if lost or purged.
func (s *SecureReportService) RegenerateArtifact(
	ctx context.Context,
	tenantID, reportID uuid.UUID,
	format ReportFormat,
	renderer *ReportRendererService,
) (*ReportArtifactRecord, error) {
	if s.snapshotRepo == nil {
		return nil, errors.New("snapshot repository required for regeneration")
	}
	snapshot, err := s.snapshotRepo.GetSnapshot(ctx, tenantID, reportID)
	if err != nil {
		return nil, fmt.Errorf("cannot regenerate: %w", err)
	}

	var content []byte
	switch format {
	case FormatHTML:
		content, err = renderer.RenderHTML(ctx, snapshot.SnapshotData)
	case FormatPDF:
		content, err = renderer.RenderPDF(ctx, snapshot.SnapshotData)
	default:
		return nil, ErrUnsupportedFormat
	}
	if err != nil {
		return nil, fmt.Errorf("rendering failed during regeneration: %w", err)
	}

	return s.StoreReportArtifact(ctx, tenantID, reportID, snapshot.AssessmentID, format, content, nil)
}
