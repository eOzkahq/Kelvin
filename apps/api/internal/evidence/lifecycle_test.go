package evidence

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockStore is a thread-safe in-memory Store for testing.
type mockStore struct {
	mu      sync.RWMutex
	records map[string]*Record
}

func newMockStore() *mockStore {
	return &mockStore{
		records: make(map[string]*Record),
	}
}

func (m *mockStore) Get(id string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[id]
	if !ok {
		return nil, errors.New("evidence: record not found")
	}
	if rec.DeletedAt != nil {
		return nil, errors.New("evidence: record not found")
	}
	return rec, nil
}

func (m *mockStore) GetByTenant(tenantID string, status EvidenceStatus, before *time.Time) ([]*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Record
	for _, rec := range m.records {
		if tenantID != "" && rec.TenantID != tenantID {
			continue
		}
		if status != "" && rec.Status != status {
			continue
		}
		if before != nil && !rec.CreatedAt.Before(*before) {
			continue
		}
		result = append(result, rec)
	}
	return result, nil
}

func (m *mockStore) UpdateStatus(id string, status EvidenceStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return errors.New("evidence: record not found")
	}
	rec.Status = status
	return nil
}

func (m *mockStore) SoftDelete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return errors.New("evidence: record not found")
	}
	now := time.Now().UTC()
	rec.DeletedAt = &now
	return nil
}

func (m *mockStore) HardDelete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, id)
	return nil
}

// mockObjectStore is an in-memory ObjectStore for testing.
type mockObjectStore struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

func newMockObjectStore() *mockObjectStore {
	return &mockObjectStore{
		objects: make(map[string][]byte),
	}
}

func (m *mockObjectStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

func (m *mockObjectStore) OverwriteWithRandom(key string, size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[key]
	if !ok {
		return errors.New("evidence: object not found")
	}
	// Overwrite with deterministic pseudo-random data (same length)
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i*7 + 3) // deterministic pattern
	}
	m.objects[key] = buf
	return nil
}

func (m *mockObjectStore) Has(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.objects[key]
	return ok
}

func TestSignerGenerateAndValidate(t *testing.T) {
	signer, err := NewSigner([]byte("01234567890123456789012345678901")) // 32 bytes
	require.NoError(t, err)

	evidenceID := "evidence-123"
	tenantID := "tenant-456"
	baseURL := "https://api.kelvin.internal/api/v1/evidence/" + evidenceID + "/download"

	url, err := signer.SignDownloadURL(evidenceID, tenantID, 15*time.Minute, baseURL)
	require.NoError(t, err)
	require.Contains(t, url, "expires=")
	require.Contains(t, url, "signature=")

	eid, tid, expires, err := signer.ValidateDownloadURL(url)
	require.NoError(t, err)
	require.Equal(t, evidenceID, eid)
	require.Equal(t, tenantID, tid)
	require.Greater(t, expires, time.Now().Unix())
}

func TestSignerInvalidKeyTooShort(t *testing.T) {
	_, err := NewSigner([]byte("short"))
	require.Error(t, err)
}

func TestSignerExpiredURL(t *testing.T) {
	signer, err := NewSigner([]byte("01234567890123456789012345678901"))
	require.NoError(t, err)

	// Manually construct a URL with an expired timestamp
	expired := time.Now().UTC().Add(-1 * time.Hour).Unix()
	url := fmt.Sprintf(
		"https://api.kelvin.internal/api/v1/evidence/evidence-123/download?expires=%d&tenant_id=tenant-456&signature=deadbeef",
		expired,
	)

	_, _, _, err = signer.ValidateDownloadURL(url)
	require.ErrorIs(t, err, ErrExpired)
}

func TestSignerTamperedSignature(t *testing.T) {
	signer, err := NewSigner([]byte("01234567890123456789012345678901"))
	require.NoError(t, err)

	baseURL := "https://api.kelvin.internal/api/v1/evidence/evidence-123/download"
	url, err := signer.SignDownloadURL("evidence-123", "tenant-456", 15*time.Minute, baseURL)
	require.NoError(t, err)

	// Tamper with the signature
	tampered := strings.Replace(url, "signature=", "signature= tampered", 1)
	_, _, _, err = signer.ValidateDownloadURL(tampered)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestSignerMissingParams(t *testing.T) {
	signer, err := NewSigner([]byte("01234567890123456789012345678901"))
	require.NoError(t, err)

	_, _, _, err = signer.ValidateDownloadURL("https://example.com/no-params")
	require.ErrorIs(t, err, ErrMalformedURL)
}

func TestSignerWrongPath(t *testing.T) {
	signer, err := NewSigner([]byte("01234567890123456789012345678901"))
	require.NoError(t, err)

	url := "https://api.kelvin.internal/api/v1/other/evidence-123/download?expires=9999999999&signature=abc"
	_, _, _, err = signer.ValidateDownloadURL(url)
	require.ErrorIs(t, err, ErrMalformedURL)
}

func TestSweepArchivesExpiredActiveRecords(t *testing.T) {
	store := newMockStore()
	objects := newMockObjectStore()
	policy := DefaultRetentionPolicy()
	policy.ActiveDays = 0 // Archive immediately for testing
	sweeper := NewSweeper(store, objects, policy)

	now := time.Now().UTC()
	oldTime := now.Add(-100 * 24 * time.Hour) // 100 days ago

	rec := &Record{
		ID:           "ev-1",
		TenantID:     "tenant-1",
		AssessmentID: "assessment-1",
		ObjectKey:    "evidence/ev-1.bin",
		ContentType:  "application/json",
		SizeBytes:    1024,
		Status:       StatusActive,
		CreatedAt:    oldTime,
	}
	// Directly insert
	store.mu.Lock()
	store.records["ev-1"] = rec
	store.mu.Unlock()

	objects.mu.Lock()
	objects.objects["evidence/ev-1.bin"] = []byte("test-data")
	objects.mu.Unlock()

	result, err := sweeper.Sweep()
	require.NoError(t, err)
	require.Equal(t, 1, result.Archived)

	updated, err := store.Get("ev-1")
	require.NoError(t, err)
	require.Equal(t, StatusArchived, updated.Status)
}

func TestSweepPurgesExpiredArchivedRecords(t *testing.T) {
	store := newMockStore()
	objects := newMockObjectStore()
	policy := DefaultRetentionPolicy()
	policy.ArchivedDays = 0 // Purge immediately for testing
	sweeper := NewSweeper(store, objects, policy)

	oldTime := time.Now().UTC().Add(-400 * 24 * time.Hour) // 400 days ago

	rec := &Record{
		ID:           "ev-2",
		TenantID:     "tenant-1",
		AssessmentID: "assessment-1",
		ObjectKey:    "evidence/ev-2.bin",
		ContentType:  "application/json",
		SizeBytes:    2048,
		Status:       StatusArchived,
		CreatedAt:    oldTime,
	}
	store.mu.Lock()
	store.records["ev-2"] = rec
	store.mu.Unlock()

	objects.mu.Lock()
	objects.objects["evidence/ev-2.bin"] = []byte("test-data-2")
	objects.mu.Unlock()

	result, err := sweeper.Sweep()
	require.NoError(t, err)
	require.Equal(t, 1, result.Purged)

	// Record should be soft-deleted
	_, err = store.Get("ev-2")
	require.Error(t, err)

	// Object should be deleted
	require.False(t, objects.Has("evidence/ev-2.bin"))
}

func TestSweepDoesNotPurgeRecentRecords(t *testing.T) {
	store := newMockStore()
	objects := newMockObjectStore()
	policy := DefaultRetentionPolicy() // 90 days active, 270 days archived
	sweeper := NewSweeper(store, objects, policy)

	recentTime := time.Now().UTC().Add(-10 * 24 * time.Hour) // 10 days ago

	rec := &Record{
		ID:           "ev-3",
		TenantID:     "tenant-1",
		AssessmentID: "assessment-1",
		ObjectKey:    "evidence/ev-3.bin",
		ContentType:  "application/json",
		SizeBytes:    512,
		Status:       StatusActive,
		CreatedAt:    recentTime,
	}
	store.mu.Lock()
	store.records["ev-3"] = rec
	store.mu.Unlock()

	objects.mu.Lock()
	objects.objects["evidence/ev-3.bin"] = []byte("test-data-3")
	objects.mu.Unlock()

	result, err := sweeper.Sweep()
	require.NoError(t, err)
	require.Equal(t, 0, result.Archived)
	require.Equal(t, 0, result.Purged)

	// Record should still be active
	updated, err := store.Get("ev-3")
	require.NoError(t, err)
	require.Equal(t, StatusActive, updated.Status)

	// Object should still exist
	require.True(t, objects.Has("evidence/ev-3.bin"))
}

func TestDefaultRetentionPolicy(t *testing.T) {
	policy := DefaultRetentionPolicy()
	require.Equal(t, 90, policy.ActiveDays)
	require.Equal(t, 270, policy.ArchivedDays)
	require.Equal(t, 7, policy.PurgeGraceDays)
}

func TestObjectOverwriteWithRandom(t *testing.T) {
	objects := newMockObjectStore()
	objects.mu.Lock()
	objects.objects["test.bin"] = []byte("original-data-12345")
	objects.mu.Unlock()

	err := objects.OverwriteWithRandom("test.bin", 15)
	require.NoError(t, err)

	data := objects.objects["test.bin"]
	require.Len(t, data, 15)
	require.NotEqual(t, []byte("original-data-12345"), data)

	// After overwrite, delete should work
	err = objects.Delete("test.bin")
	require.NoError(t, err)
	require.False(t, objects.Has("test.bin"))
}
