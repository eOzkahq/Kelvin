package evidence_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

func TestRetentionManager_ArchiveTransition(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	policy := evidence.DefaultRetentionPolicy() // 90 days active, 270 days archived
	mgr := evidence.NewRetentionManager(repo, nil, policy, nil)

	tenantID := uuid.New().String()
	itemID := uuid.New().String()
	created := time.Now().UTC().AddDate(0, 0, -95) // 95 days old

	item := &evidence.EvidenceItem{
		ID:             itemID,
		TenantID:       tenantID,
		ProjectID:      uuid.New().String(),
		AssessmentID:   uuid.New().String(),
		JobID:          uuid.New().String(),
		EvidenceType:   evidence.TypeHTTPObservation,
		InlineContent:  "GET /test HTTP/1.1\r\n\r\n200 OK",
		ChecksumSHA256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Status:         evidence.StatusActive,
		CreatedAt:      created,
		ExpiresAt:      created.AddDate(0, 0, 90),
	}

	require.NoError(t, repo.SaveEvidence(ctx, item))

	res, err := mgr.EnforceRetentionSweep(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Archived)
	assert.Equal(t, 0, res.Purged)

	updated, err := repo.GetEvidenceByID(ctx, tenantID, itemID)
	require.NoError(t, err)
	assert.Equal(t, evidence.StatusArchived, updated.Status)
	assert.NotEmpty(t, updated.InlineContent) // preserved in cold archive
}

func TestRetentionManager_PurgeTransition(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	key := [32]byte{1, 2, 3, 4}
	storage := evidence.NewMemoryStorageService(key)
	policy := evidence.DefaultRetentionPolicy()
	mgr := evidence.NewRetentionManager(repo, storage, policy, nil)

	tenantID := uuid.New().String()
	itemID := uuid.New().String()
	created := time.Now().UTC().AddDate(0, 0, -370) // 370 days old (past 90+270)

	// Save to storage
	_, err := storage.PutObject(ctx, tenantID, itemID, "text/plain", []byte("Sensitive storage data"))
	require.NoError(t, err)

	item := &evidence.EvidenceItem{
		ID:             itemID,
		TenantID:       tenantID,
		ProjectID:      uuid.New().String(),
		AssessmentID:   uuid.New().String(),
		JobID:          uuid.New().String(),
		EvidenceType:   evidence.TypeHTTPObservation,
		StorageRef:     evidence.BuildStorageKey(tenantID, itemID),
		InlineContent:  "Temporary snippet",
		ChecksumSHA256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Status:         evidence.StatusArchived,
		CreatedAt:      created,
		ExpiresAt:      created.AddDate(0, 0, 90),
	}
	require.NoError(t, repo.SaveEvidence(ctx, item))

	res, err := mgr.EnforceRetentionSweep(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Purged)

	updated, err := repo.GetEvidenceByID(ctx, tenantID, itemID)
	require.NoError(t, err)
	assert.Equal(t, evidence.StatusPurged, updated.Status)
	assert.Empty(t, updated.InlineContent)
	assert.Empty(t, updated.StorageRef)
	assert.NotNil(t, updated.WipedAt)

	// Verify storage object was deleted
	_, _, err = storage.GetObject(ctx, tenantID, itemID)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrObjectNotFound)
}

func TestRetentionManager_LegalHoldProtection(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	policy := evidence.DefaultRetentionPolicy()
	mgr := evidence.NewRetentionManager(repo, nil, policy, nil)

	tenantID := uuid.New().String()
	itemID := uuid.New().String()
	created := time.Now().UTC().AddDate(0, 0, -400) // very old

	item := &evidence.EvidenceItem{
		ID:              itemID,
		TenantID:        tenantID,
		ProjectID:       uuid.New().String(),
		AssessmentID:    uuid.New().String(),
		JobID:           uuid.New().String(),
		EvidenceType:    evidence.TypeHTTPObservation,
		InlineContent:   "Under pending subpoena",
		ChecksumSHA256:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Status:          evidence.StatusArchived,
		IsLegalHold:     true,
		LegalHoldReason: "Regulatory Audit 2026",
		CreatedAt:       created,
		ExpiresAt:       created.AddDate(0, 0, 90),
	}
	require.NoError(t, repo.SaveEvidence(ctx, item))

	// Sweep must protect item
	res, err := mgr.EnforceRetentionSweep(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, res.HeldProtected)
	assert.Equal(t, 0, res.Purged)

	// Manual purge without force fails
	err = mgr.PurgeEvidenceItem(ctx, tenantID, itemID, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrLegalHoldEnforced)

	// Manual purge with force succeeds
	err = mgr.PurgeEvidenceItem(ctx, tenantID, itemID, true)
	require.NoError(t, err)

	updated, err := repo.GetEvidenceByID(ctx, tenantID, itemID)
	require.NoError(t, err)
	assert.Equal(t, evidence.StatusPurged, updated.Status)
}

type failingStorage struct{}

func (f *failingStorage) PutObject(_ context.Context, _, _, _ string, _ []byte) (*evidence.ObjectMetadata, error) {
	return nil, nil
}
func (f *failingStorage) GetObject(_ context.Context, _, _ string) ([]byte, *evidence.ObjectMetadata, error) {
	return nil, nil, nil
}
func (f *failingStorage) GetMetadata(_ context.Context, _, _ string) (*evidence.ObjectMetadata, error) {
	return nil, nil
}
func (f *failingStorage) DeleteObject(_ context.Context, _, _ string) error {
	return nil
}
func (f *failingStorage) SecurePurge(_ context.Context, _, _ string) error {
	return errors.New("simulated S3 connectivity failure")
}

func TestRetentionManager_PartialStorageFailure(t *testing.T) {
	ctx := context.Background()
	repo := evidence.NewMemoryRepository()
	policy := evidence.DefaultRetentionPolicy()
	mgr := evidence.NewRetentionManager(repo, &failingStorage{}, policy, nil)

	tenantID := uuid.New().String()
	itemID := uuid.New().String()
	created := time.Now().UTC().AddDate(0, 0, -400)

	item := &evidence.EvidenceItem{
		ID:             itemID,
		TenantID:       tenantID,
		ProjectID:      uuid.New().String(),
		AssessmentID:   uuid.New().String(),
		JobID:          uuid.New().String(),
		EvidenceType:   evidence.TypeHTTPObservation,
		StorageRef:     evidence.BuildStorageKey(tenantID, itemID),
		ChecksumSHA256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Status:         evidence.StatusArchived,
		CreatedAt:      created,
		ExpiresAt:      created.AddDate(0, 0, 90),
	}
	require.NoError(t, repo.SaveEvidence(ctx, item))

	res, err := mgr.EnforceRetentionSweep(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, res.Failed)
	assert.Equal(t, 0, res.Purged)

	updated, err := repo.GetEvidenceByID(ctx, tenantID, itemID)
	require.NoError(t, err)
	assert.Equal(t, evidence.StatusPurgeFailed, updated.Status)
	assert.Equal(t, 1, updated.PurgeRetryCount)
}
