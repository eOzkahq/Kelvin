// Package evidence provides storage abstraction, pluggable adapters,
// AES-256-GCM at-rest encryption, and integrity verification for evidence blobs.
//
// See docs/architecture/SECURE_EVIDENCE_STORAGE_SERVICE.md.
package evidence

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Storage error definitions.
var (
	// ErrObjectNotFound is returned when an evidence binary does not exist.
	ErrObjectNotFound = errors.New("evidence storage: object not found")

	// ErrCorruptedObject is returned when decryption fails or sha256 checksum does not match.
	ErrCorruptedObject = errors.New("evidence storage: object integrity check failed or corrupted ciphertext")

	// ErrStorageUnavailable is returned when the storage adapter cannot be contacted.
	ErrStorageUnavailable = errors.New("evidence storage: backend unavailable")

	// ErrInvalidEncryptionKey is returned when the AES key is not 32 bytes.
	ErrInvalidEncryptionKey = errors.New("evidence storage: encryption key must be 32 bytes for AES-256")
)

// ObjectMetadata encapsulates technical attributes for a stored evidence binary.
type ObjectMetadata struct {
	TenantID       string    `json:"tenant_id"`
	ObjectID       string    `json:"object_id"`
	StorageKey     string    `json:"storage_key"`
	ContentType    string    `json:"content_type"`
	SizeBytes      int64     `json:"size_bytes"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	Encrypted      bool      `json:"encrypted"`
	CreatedAt      time.Time `json:"created_at"`
}

// StorageService defines the decoupling abstraction for storing and retrieving evidence blobs.
type StorageService interface {
	PutObject(ctx context.Context, tenantID, objectID, contentType string, data []byte) (*ObjectMetadata, error)
	GetObject(ctx context.Context, tenantID, objectID string) ([]byte, *ObjectMetadata, error)
	GetMetadata(ctx context.Context, tenantID, objectID string) (*ObjectMetadata, error)
	DeleteObject(ctx context.Context, tenantID, objectID string) error
	SecurePurge(ctx context.Context, tenantID, objectID string) error
}

// BuildStorageKey returns the non-guessable tenant-partitioned object key.
func BuildStorageKey(tenantID, objectID string) string {
	return fmt.Sprintf("evidence/%s/%s", tenantID, objectID)
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM with a fresh random 12-byte nonce.
func EncryptAESGCM(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidEncryptionKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Output format: [12-byte nonce][ciphertext + 16-byte auth tag]
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts ciphertext produced by EncryptAESGCM.
func DecryptAESGCM(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidEncryptionKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCorruptedObject
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrCorruptedObject
	}

	return plaintext, nil
}

// EncryptedLocalStorage is a filesystem-based storage adapter that encrypts
// every object at rest using AES-256-GCM.
type EncryptedLocalStorage struct {
	baseDir string
	key     [32]byte
	mu      sync.RWMutex
}

// NewEncryptedLocalStorage constructs an EncryptedLocalStorage adapter.
func NewEncryptedLocalStorage(baseDir string, key [32]byte) (*EncryptedLocalStorage, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create base storage dir: %w", err)
	}
	return &EncryptedLocalStorage{
		baseDir: baseDir,
		key:     key,
	}, nil
}

func (s *EncryptedLocalStorage) pathsFor(tenantID, objectID string) (blobPath, metaPath string) {
	dir := filepath.Join(s.baseDir, "evidence", tenantID)
	blobPath = filepath.Join(dir, objectID+".bin")
	metaPath = filepath.Join(dir, objectID+".meta.json")
	return blobPath, metaPath
}

// PutObject stores and encrypts an evidence blob.
func (s *EncryptedLocalStorage) PutObject(
	_ context.Context,
	tenantID, objectID, contentType string,
	data []byte,
) (*ObjectMetadata, error) {
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id: %w", ErrTenantMismatch, err)
	}
	if objectID == "" {
		objectID = uuid.New().String()
	}

	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	encryptedBytes, err := EncryptAESGCM(s.key[:], data)
	if err != nil {
		return nil, fmt.Errorf("encrypt evidence data: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	blobPath, metaPath := s.pathsFor(tenantID, objectID)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	if err := os.WriteFile(blobPath, encryptedBytes, 0600); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	meta := &ObjectMetadata{
		TenantID:       tenantID,
		ObjectID:       objectID,
		StorageKey:     BuildStorageKey(tenantID, objectID),
		ContentType:    contentType,
		SizeBytes:      int64(len(data)),
		ChecksumSHA256: checksum,
		Encrypted:      true,
		CreatedAt:      time.Now().UTC(),
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		_ = os.Remove(blobPath)
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, metaBytes, 0600); err != nil {
		_ = os.Remove(blobPath)
		return nil, fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	return meta, nil
}

// GetObject retrieves and decrypts an evidence blob with integrity verification.
func (s *EncryptedLocalStorage) GetObject(
	_ context.Context,
	tenantID, objectID string,
) ([]byte, *ObjectMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blobPath, metaPath := s.pathsFor(tenantID, objectID)

	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrObjectNotFound
		}
		return nil, nil, fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	var meta ObjectMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, nil, ErrCorruptedObject
	}

	if meta.TenantID != tenantID {
		return nil, nil, ErrTenantMismatch
	}

	encryptedData, err := os.ReadFile(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrObjectNotFound
		}
		return nil, nil, fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	plaintext, err := DecryptAESGCM(s.key[:], encryptedData)
	if err != nil {
		return nil, nil, ErrCorruptedObject
	}

	// Verify SHA-256 digest against metadata
	computedHash := sha256.Sum256(plaintext)
	if hex.EncodeToString(computedHash[:]) != meta.ChecksumSHA256 {
		return nil, nil, ErrCorruptedObject
	}

	return plaintext, &meta, nil
}

// GetMetadata fetches object metadata without retrieving and decrypting the blob.
func (s *EncryptedLocalStorage) GetMetadata(
	_ context.Context,
	tenantID, objectID string,
) (*ObjectMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, metaPath := s.pathsFor(tenantID, objectID)
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrObjectNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	var meta ObjectMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, ErrCorruptedObject
	}

	if meta.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	return &meta, nil
}

// DeleteObject removes an evidence object and metadata.
func (s *EncryptedLocalStorage) DeleteObject(_ context.Context, tenantID, objectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blobPath, metaPath := s.pathsFor(tenantID, objectID)
	_ = os.Remove(blobPath)
	_ = os.Remove(metaPath)
	return nil
}

// SecurePurge overwrites the evidence blob with cryptographic random data before deleting it.
func (s *EncryptedLocalStorage) SecurePurge(ctx context.Context, tenantID, objectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blobPath, metaPath := s.pathsFor(tenantID, objectID)
	info, err := os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = os.Remove(metaPath)
			return nil
		}
		return fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}

	randomBytes := make([]byte, info.Size())
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return fmt.Errorf("generate random overwrite bytes: %w", err)
	}

	// Overwrite on disk
	_ = os.WriteFile(blobPath, randomBytes, 0600)
	_ = os.Remove(blobPath)
	_ = os.Remove(metaPath)
	return nil
}

// MemoryStorageService is an in-memory implementation of StorageService.
type MemoryStorageService struct {
	mu       sync.RWMutex
	key      [32]byte
	blobs    map[string][]byte
	metadata map[string]*ObjectMetadata
}

// NewMemoryStorageService constructs a memory storage service.
func NewMemoryStorageService(key [32]byte) *MemoryStorageService {
	return &MemoryStorageService{
		key:      key,
		blobs:    make(map[string][]byte),
		metadata: make(map[string]*ObjectMetadata),
	}
}

// PutObject encrypts and stores the payload in memory.
func (m *MemoryStorageService) PutObject(
	_ context.Context,
	tenantID, objectID, contentType string,
	data []byte,
) (*ObjectMetadata, error) {
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id: %w", ErrTenantMismatch, err)
	}
	if objectID == "" {
		objectID = uuid.New().String()
	}

	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	encryptedBytes, err := EncryptAESGCM(m.key[:], data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	storageKey := BuildStorageKey(tenantID, objectID)
	m.blobs[storageKey] = encryptedBytes

	meta := &ObjectMetadata{
		TenantID:       tenantID,
		ObjectID:       objectID,
		StorageKey:     storageKey,
		ContentType:    contentType,
		SizeBytes:      int64(len(data)),
		ChecksumSHA256: checksum,
		Encrypted:      true,
		CreatedAt:      time.Now().UTC(),
	}
	m.metadata[storageKey] = meta

	return meta, nil
}

// GetObject retrieves and decrypts the in-memory object.
func (m *MemoryStorageService) GetObject(
	_ context.Context,
	tenantID, objectID string,
) ([]byte, *ObjectMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storageKey := BuildStorageKey(tenantID, objectID)
	encryptedBytes, ok := m.blobs[storageKey]
	if !ok {
		return nil, nil, ErrObjectNotFound
	}
	meta := m.metadata[storageKey]
	if meta == nil || meta.TenantID != tenantID {
		return nil, nil, ErrTenantMismatch
	}

	plaintext, err := DecryptAESGCM(m.key[:], encryptedBytes)
	if err != nil {
		return nil, nil, ErrCorruptedObject
	}

	hash := sha256.Sum256(plaintext)
	if hex.EncodeToString(hash[:]) != meta.ChecksumSHA256 {
		return nil, nil, ErrCorruptedObject
	}

	return plaintext, meta, nil
}

// GetMetadata retrieves metadata without decrypting payload.
func (m *MemoryStorageService) GetMetadata(
	_ context.Context,
	tenantID, objectID string,
) (*ObjectMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storageKey := BuildStorageKey(tenantID, objectID)
	meta, ok := m.metadata[storageKey]
	if !ok {
		return nil, ErrObjectNotFound
	}
	if meta.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return meta, nil
}

// DeleteObject deletes the object and metadata.
func (m *MemoryStorageService) DeleteObject(_ context.Context, tenantID, objectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	storageKey := BuildStorageKey(tenantID, objectID)
	delete(m.blobs, storageKey)
	delete(m.metadata, storageKey)
	return nil
}

// SecurePurge overwrites memory buffer with random data then removes it.
func (m *MemoryStorageService) SecurePurge(ctx context.Context, tenantID, objectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	storageKey := BuildStorageKey(tenantID, objectID)
	if blob, ok := m.blobs[storageKey]; ok {
		_, _ = rand.Read(blob)
		delete(m.blobs, storageKey)
	}
	delete(m.metadata, storageKey)
	return nil
}
