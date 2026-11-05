package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// MaxArtifactSizeBytes is 50 MB per storage artifact.
	MaxArtifactSizeBytes int64 = 50 * 1024 * 1024

	// DefaultSignedURLExpiry is 300 seconds (5 minutes).
	DefaultSignedURLExpiry = 300 * time.Second
)

var (
	ErrObjectNotFound     = errors.New("storage: object not found")
	ErrFileTooLarge        = errors.New("storage: file exceeds maximum allowable size (50 MB)")
	ErrInvalidContentType  = errors.New("storage: invalid or unauthorized content type")
	ErrCorruptedPayload    = errors.New("storage: payload magic bytes do not match declared content type")
	ErrInvalidStoragePath  = errors.New("storage: storage path must conform to {tenant_id}/{assessment_id}/{file_id}")
	ErrCrossTenantAccess   = errors.New("storage: cross-tenant access violation")
)

// AllowedContentTypes defines whitelisted MIME types for evidence and report artifacts.
var AllowedContentTypes = map[string]bool{
	"application/pdf":              true,
	"text/html; charset=utf-8":     true,
	"text/html":                    true,
	"application/json":             true,
	"text/plain; charset=utf-8":    true,
	"text/plain":                   true,
	"application/xml":              true,
	"text/xml":                     true,
	"application/octet-stream":     true,
}

// StorageService defines the decoupling boundary for object storage.
type StorageService interface {
	Upload(ctx context.Context, bucket, objectPath, contentType string, data []byte) error
	Download(ctx context.Context, bucket, objectPath string) ([]byte, error)
	GetSignedURL(ctx context.Context, bucket, objectPath string, expiry time.Duration) (string, error)
	Delete(ctx context.Context, bucket, objectPath string) error
	VerifyTenantAccess(tenantID, objectPath string) error
}

// Config encapsulates Supabase Storage settings.
type Config struct {
	URL             string        `mapstructure:"url"`
	ServiceRoleKey  string        `mapstructure:"service_role_key"` // Sensitive
	ReportsBucket   string        `mapstructure:"reports_bucket"`
	EvidenceBucket  string        `mapstructure:"evidence_bucket"`
	SignedURLExpiry time.Duration `mapstructure:"signed_url_expiry"`
}

// ValidateStoragePath ensures tenant isolation by checking the prefix structure.
// Expected structure: {tenant_id}/{assessment_id}/{file_id}
func ValidateStoragePath(objectPath, expectedTenantID string) error {
	clean := path.Clean(strings.TrimPrefix(objectPath, "/"))
	parts := strings.Split(clean, "/")
	if len(parts) < 3 {
		return fmt.Errorf("%w: path requires at least tenant/assessment/file", ErrInvalidStoragePath)
	}

	pathTenant := parts[0]
	if expectedTenantID != "" && pathTenant != expectedTenantID {
		return fmt.Errorf("%w: path tenant %s does not match expected %s", ErrCrossTenantAccess, pathTenant, expectedTenantID)
	}

	return nil
}

// ValidateArtifact validates file size, declared content type, and magic bytes.
func ValidateArtifact(contentType string, data []byte) error {
	if int64(len(data)) > MaxArtifactSizeBytes {
		return ErrFileTooLarge
	}

	normType := strings.ToLower(strings.TrimSpace(contentType))
	if !AllowedContentTypes[normType] {
		return fmt.Errorf("%w: %s", ErrInvalidContentType, contentType)
	}

	// Verify magic bytes for critical formats
	if strings.Contains(normType, "application/pdf") {
		if !bytes.HasPrefix(data, []byte("%PDF-")) {
			return fmt.Errorf("%w: declared PDF does not begin with %%PDF- header", ErrCorruptedPayload)
		}
	} else if strings.Contains(normType, "application/json") {
		var js interface{}
		if err := json.Unmarshal(data, &js); err != nil {
			return fmt.Errorf("%w: invalid JSON payload: %v", ErrCorruptedPayload, err)
		}
	}

	return nil
}

// SupabaseStorageProvider implements StorageService for Supabase Storage (S3 / REST API).
type SupabaseStorageProvider struct {
	cfg        Config
	httpClient *http.Client
	baseURL    *url.URL
}

// NewSupabaseStorageProvider creates a Supabase Storage provider.
func NewSupabaseStorageProvider(cfg Config) (*SupabaseStorageProvider, error) {
	if cfg.URL == "" {
		return nil, errors.New("supabase storage: URL is required")
	}
	if cfg.ServiceRoleKey == "" {
		return nil, errors.New("supabase storage: service role key is required")
	}
	if cfg.SignedURLExpiry <= 0 {
		cfg.SignedURLExpiry = DefaultSignedURLExpiry
	}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("supabase storage: invalid base URL: %w", err)
	}

	return &SupabaseStorageProvider{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    parsed,
	}, nil
}

func (s *SupabaseStorageProvider) Upload(ctx context.Context, bucket, objectPath, contentType string, data []byte) error {
	if err := ValidateArtifact(contentType, data); err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/storage/v1/object/%s/%s", strings.TrimRight(s.cfg.URL, "/"), bucket, strings.TrimLeft(objectPath, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.ServiceRoleKey)
	req.Header.Set("apikey", s.cfg.ServiceRoleKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-upsert", "true")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("supabase storage: upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("supabase storage: upload error HTTP %d", resp.StatusCode)
	}

	return nil
}

func (s *SupabaseStorageProvider) Download(ctx context.Context, bucket, objectPath string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/storage/v1/object/%s/%s", strings.TrimRight(s.cfg.URL, "/"), bucket, strings.TrimLeft(objectPath, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.ServiceRoleKey)
	req.Header.Set("apikey", s.cfg.ServiceRoleKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("supabase storage: download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrObjectNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("supabase storage: download error HTTP %d", resp.StatusCode)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *SupabaseStorageProvider) GetSignedURL(ctx context.Context, bucket, objectPath string, expiry time.Duration) (string, error) {
	if expiry <= 0 || expiry > DefaultSignedURLExpiry {
		expiry = DefaultSignedURLExpiry
	}

	expiresAt := time.Now().Add(expiry).Unix()
	mac := hmac.New(sha256.New, []byte(s.cfg.ServiceRoleKey))
	dataToSign := fmt.Sprintf("%s/%s:%d", bucket, objectPath, expiresAt)
	mac.Write([]byte(dataToSign))
	signature := hex.EncodeToString(mac.Sum(nil))

	signedURL := fmt.Sprintf("%s/storage/v1/object/sign/%s/%s?token=%s&expires=%d",
		strings.TrimRight(s.cfg.URL, "/"), bucket, strings.TrimLeft(objectPath, "/"), signature, expiresAt)

	return signedURL, nil
}

func (s *SupabaseStorageProvider) Delete(ctx context.Context, bucket, objectPath string) error {
	endpoint := fmt.Sprintf("%s/storage/v1/object/%s/%s", strings.TrimRight(s.cfg.URL, "/"), bucket, strings.TrimLeft(objectPath, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.ServiceRoleKey)
	req.Header.Set("apikey", s.cfg.ServiceRoleKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("supabase storage: delete request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrObjectNotFound
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("supabase storage: delete error HTTP %d", resp.StatusCode)
	}

	return nil
}

func (s *SupabaseStorageProvider) VerifyTenantAccess(tenantID, objectPath string) error {
	return ValidateStoragePath(objectPath, tenantID)
}

// MemoryStorageProvider implements in-memory StorageService for deterministic testing.
type MemoryStorageProvider struct {
	mu      sync.RWMutex
	objects map[string][]byte
	secret  string
}

// NewMemoryStorageProvider creates a new in-memory storage provider.
func NewMemoryStorageProvider(secret string) *MemoryStorageProvider {
	if secret == "" {
		secret = "test-secret-key-for-memory-provider"
	}
	return &MemoryStorageProvider{
		objects: make(map[string][]byte),
		secret:  secret,
	}
}

func (m *MemoryStorageProvider) Upload(_ context.Context, bucket, objectPath, contentType string, data []byte) error {
	if err := ValidateArtifact(contentType, data); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s", bucket, strings.TrimLeft(objectPath, "/"))
	copied := make([]byte, len(data))
	copy(copied, data)
	m.objects[key] = copied
	return nil
}

func (m *MemoryStorageProvider) Download(_ context.Context, bucket, objectPath string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", bucket, strings.TrimLeft(objectPath, "/"))
	data, ok := m.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}

	copied := make([]byte, len(data))
	copy(copied, data)
	return copied, nil
}

func (m *MemoryStorageProvider) GetSignedURL(_ context.Context, bucket, objectPath string, expiry time.Duration) (string, error) {
	if expiry <= 0 || expiry > DefaultSignedURLExpiry {
		expiry = DefaultSignedURLExpiry
	}

	expiresAt := time.Now().Add(expiry).Unix()
	mac := hmac.New(sha256.New, []byte(m.secret))
	dataToSign := fmt.Sprintf("%s/%s:%d", bucket, objectPath, expiresAt)
	mac.Write([]byte(dataToSign))
	signature := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("https://storage.kelvin.internal/v1/object/sign/%s/%s?token=%s&expires=%d",
		bucket, strings.TrimLeft(objectPath, "/"), signature, expiresAt), nil
}

func (m *MemoryStorageProvider) Delete(_ context.Context, bucket, objectPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s", bucket, strings.TrimLeft(objectPath, "/"))
	if _, ok := m.objects[key]; !ok {
		return ErrObjectNotFound
	}

	delete(m.objects, key)
	return nil
}

func (m *MemoryStorageProvider) VerifyTenantAccess(tenantID, objectPath string) error {
	return ValidateStoragePath(objectPath, tenantID)
}
