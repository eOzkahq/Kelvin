package evidence_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

func generateRandomKey() [32]byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k
}

func TestAESGCM_EncryptionAndDecryption(t *testing.T) {
	key := generateRandomKey()
	plaintext := []byte("secret sensitive raw payload with tokens: eyJhbGciOi...")

	ciphertext, err := evidence.EncryptAESGCM(key[:], plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := evidence.DecryptAESGCM(key[:], ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	t.Run("tampered ciphertext fails", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)-1] ^= 0xFF

		_, err := evidence.DecryptAESGCM(key[:], tampered)
		require.Error(t, err)
		assert.ErrorIs(t, err, evidence.ErrCorruptedObject)
	})

	t.Run("invalid key size fails", func(t *testing.T) {
		_, err := evidence.EncryptAESGCM([]byte("too-short"), plaintext)
		require.Error(t, err)
		assert.ErrorIs(t, err, evidence.ErrInvalidEncryptionKey)
	})
}

func TestEncryptedLocalStorage(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "kelvin-evidence-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	key := generateRandomKey()
	storage, err := evidence.NewEncryptedLocalStorage(tempDir, key)
	require.NoError(t, err)

	tenantID := uuid.New().String()
	objectID := uuid.New().String()
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")

	// PutObject
	meta, err := storage.PutObject(ctx, tenantID, objectID, "text/plain", payload)
	require.NoError(t, err)
	assert.Equal(t, tenantID, meta.TenantID)
	assert.Equal(t, objectID, meta.ObjectID)
	assert.True(t, meta.Encrypted)
	assert.Equal(t, int64(len(payload)), meta.SizeBytes)

	// GetMetadata
	fetchedMeta, err := storage.GetMetadata(ctx, tenantID, objectID)
	require.NoError(t, err)
	assert.Equal(t, meta.ChecksumSHA256, fetchedMeta.ChecksumSHA256)

	// GetObject
	retrieved, retMeta, err := storage.GetObject(ctx, tenantID, objectID)
	require.NoError(t, err)
	assert.Equal(t, payload, retrieved)
	assert.Equal(t, meta.ChecksumSHA256, retMeta.ChecksumSHA256)

	// Cross-tenant access rejection
	tenantOther := uuid.New().String()
	_, _, err = storage.GetObject(ctx, tenantOther, objectID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrObjectNotFound)

	// Corrupted file handling
	blobPath := filepath.Join(tempDir, "evidence", tenantID, objectID+".bin")
	_ = os.WriteFile(blobPath, []byte("corrupted data not encrypted"), 0600)
	_, _, err = storage.GetObject(ctx, tenantID, objectID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrCorruptedObject)

	// Missing object handling
	_, _, err = storage.GetObject(ctx, tenantID, "missing-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrObjectNotFound)

	// Secure purge
	err = storage.SecurePurge(ctx, tenantID, objectID)
	require.NoError(t, err)
	_, _, err = storage.GetObject(ctx, tenantID, objectID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrObjectNotFound)
}

func TestMemoryStorageService(t *testing.T) {
	ctx := context.Background()
	key := generateRandomKey()
	storage := evidence.NewMemoryStorageService(key)

	tenantID := uuid.New().String()
	objectID := uuid.New().String()
	payload := []byte("TLS Certificate Chain PEM: -----BEGIN CERTIFICATE-----")

	meta, err := storage.PutObject(ctx, tenantID, objectID, "application/x-pem-file", payload)
	require.NoError(t, err)
	assert.Equal(t, tenantID, meta.TenantID)

	retrieved, retMeta, err := storage.GetObject(ctx, tenantID, objectID)
	require.NoError(t, err)
	assert.Equal(t, payload, retrieved)
	assert.Equal(t, meta.ChecksumSHA256, retMeta.ChecksumSHA256)

	// Cross tenant access
	_, _, err = storage.GetObject(ctx, uuid.New().String(), objectID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrObjectNotFound)

	// Delete
	err = storage.DeleteObject(ctx, tenantID, objectID)
	require.NoError(t, err)
	_, _, err = storage.GetObject(ctx, tenantID, objectID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrObjectNotFound)
}
