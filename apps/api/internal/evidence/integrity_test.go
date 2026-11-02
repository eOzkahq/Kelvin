package evidence_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

func TestVerifyPayload_Success(t *testing.T) {
	ctx := context.Background()
	verifier := evidence.NewIntegrityVerifier(nil)

	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\"}")
	hash := sha256.Sum256(payload)
	expectedDigest := hex.EncodeToString(hash[:])

	prov := evidence.ScannerProvenance{
		ScannerName:  "builtin.http_security_headers",
		AssessmentID: uuid.New().String(),
		JobID:        uuid.New().String(),
		CapturedAt:   time.Now().UTC(),
	}

	res, err := verifier.VerifyPayload(ctx, uuid.New().String(), uuid.New().String(), expectedDigest, payload, prov, "analyst@kelvin.local")
	require.NoError(t, err)
	assert.Equal(t, evidence.IntegrityStatusVerified, res.Status)
	assert.False(t, res.AlertTriggered)
	assert.Equal(t, expectedDigest, res.CalculatedDigest)
}

func TestVerifyPayload_TamperedMismatch(t *testing.T) {
	ctx := context.Background()
	verifier := evidence.NewIntegrityVerifier(nil)

	originalPayload := []byte("Original Unmodified Evidence")
	hash := sha256.Sum256(originalPayload)
	expectedDigest := hex.EncodeToString(hash[:])

	tamperedPayload := []byte("Tampered Malicious Modification")

	prov := evidence.ScannerProvenance{
		ScannerName:  "zap",
		AssessmentID: uuid.New().String(),
		JobID:        uuid.New().String(),
		CapturedAt:   time.Now().UTC(),
	}

	res, err := verifier.VerifyPayload(ctx, uuid.New().String(), uuid.New().String(), expectedDigest, tamperedPayload, prov, "audit_service")
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrIntegrityMismatch)
	assert.Equal(t, evidence.IntegrityStatusTampered, res.Status)
	assert.True(t, res.AlertTriggered)
	assert.NotEqual(t, expectedDigest, res.CalculatedDigest)
}

func TestVerifyItem_InlineAndStorage(t *testing.T) {
	ctx := context.Background()
	verifier := evidence.NewIntegrityVerifier(nil)

	content := []byte("X-Frame-Options: SAMEORIGIN")
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])

	tenantID := uuid.New().String()
	evidenceID := uuid.New().String()

	item := &evidence.EvidenceItem{
		ID:             evidenceID,
		TenantID:       tenantID,
		ProjectID:      uuid.New().String(),
		AssessmentID:   uuid.New().String(),
		JobID:          uuid.New().String(),
		EvidenceType:   evidence.TypeSecurityHeaderDiff,
		InlineContent:  string(content),
		ChecksumSHA256: checksum,
		SizeBytes:      int64(len(content)),
		Status:         evidence.StatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	// 1. Inline verification
	res, err := verifier.VerifyItem(ctx, item, nil, "system_verifier")
	require.NoError(t, err)
	assert.Equal(t, evidence.IntegrityStatusVerified, res.Status)

	// 2. Storage verification
	key := [32]byte{1, 2, 3, 4, 5}
	storage := evidence.NewMemoryStorageService(key)
	storageItemID := uuid.New().String()
	largeContent := []byte("Larger evidence payload stored in encrypted object store...")
	lHash := sha256.Sum256(largeContent)
	lChecksum := hex.EncodeToString(lHash[:])

	_, err = storage.PutObject(ctx, tenantID, storageItemID, "text/plain", largeContent)
	require.NoError(t, err)

	storageItem := &evidence.EvidenceItem{
		ID:             storageItemID,
		TenantID:       tenantID,
		ProjectID:      uuid.New().String(),
		AssessmentID:   uuid.New().String(),
		JobID:          uuid.New().String(),
		EvidenceType:   evidence.TypeHTTPObservation,
		StorageRef:     evidence.BuildStorageKey(tenantID, storageItemID),
		ChecksumSHA256: lChecksum,
		SizeBytes:      int64(len(largeContent)),
		Status:         evidence.StatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	storageRes, err := verifier.VerifyItem(ctx, storageItem, storage, "system_verifier")
	require.NoError(t, err)
	assert.Equal(t, evidence.IntegrityStatusVerified, storageRes.Status)

	// 3. Quarantined evidence rejects verification
	storageItem.Status = evidence.StatusPurging
	_, err = verifier.VerifyItem(ctx, storageItem, storage, "system_verifier")
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrEvidenceQuarantined)
}
