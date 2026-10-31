package idempotency

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// fakeUniversalClient implements redis.UniversalClient with an in-memory map,
// sufficient for testing RedisStore without a real Redis server.
type fakeUniversalClient struct {
	redis.UniversalClient // embed for unused methods
	mu                    sync.RWMutex
	data                  map[string]string
}

func newFakeUniversalClient() *fakeUniversalClient {
	return &fakeUniversalClient{
		data: make(map[string]string),
	}
}

func (f *fakeUniversalClient) Get(ctx context.Context, key string) *redis.StringCmd {
	f.mu.RLock()
	defer f.mu.RUnlock()
	cmd := redis.NewStringCmd(ctx)
	val, ok := f.data[key]
	if !ok {
		cmd.SetErr(redis.Nil)
		return cmd
	}
	cmd.SetVal(val)
	return cmd
}

func (f *fakeUniversalClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redis.NewBoolCmd(ctx)
	if _, exists := f.data[key]; exists {
		cmd.SetVal(false)
		return cmd
	}
	f.data[key] = string(value.([]byte))
	cmd.SetVal(true)
	return cmd
}

func (f *fakeUniversalClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redis.NewStatusCmd(ctx)
	f.data[key] = string(value.([]byte))
	return cmd
}

func TestStoreKeyCrossTenantIsolation(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	key := "deadbeef-1234-5678-9abc-def123456789"

	k1 := storeKey(tenantA, key)
	k2 := storeKey(tenantB, key)

	require.NotEqual(t, k1, k2, "store keys must differ across tenants")
	require.Contains(t, k1, tenantA.String())
	require.Contains(t, k2, tenantB.String())
	require.Contains(t, k1, key)
	require.Contains(t, k2, key)
}

func TestRedisStoreRoundTrip(t *testing.T) {
	client := newFakeUniversalClient()
	store := NewRedisStore(client, time.Hour)
	ctx := context.Background()

	tenantID := uuid.New()
	idemKey := uuid.New()
	sk := storeKey(tenantID, idemKey.String())

	// Key not found initially.
	_, err := store.Get(ctx, sk)
	require.ErrorIs(t, err, ErrNotFound)

	// Create IN_PROGRESS.
	err = store.SetInProgress(ctx, sk, tenantID.String(), "abc123hash")
	require.NoError(t, err)

	// Duplicate SET IN_PROGRESS should fail with ErrAlreadyExists.
	err = store.SetInProgress(ctx, sk, tenantID.String(), "abc123hash")
	require.ErrorIs(t, err, ErrAlreadyExists)

	// Get should return IN_PROGRESS.
	rec, err := store.Get(ctx, sk)
	require.NoError(t, err)
	require.Equal(t, tenantID.String(), rec.TenantID)
	require.Equal(t, StatusInProgress, rec.Status)
	require.Equal(t, "abc123hash", rec.PayloadHash)
	require.NotZero(t, rec.CreatedAt)

	// Complete the record.
	err = store.SetCompleted(ctx, sk, 201, []byte(`{"id":"job-1"}`), map[string]string{"Content-Type": "application/json"})
	require.NoError(t, err)

	// Get should now return COMPLETED with cached response.
	rec, err = store.Get(ctx, sk)
	require.NoError(t, err)
	require.Equal(t, StatusCompleted, rec.Status)
	require.Equal(t, 201, rec.ResponseCode)
	require.Equal(t, `{"id":"job-1"}`, string(rec.ResponseBody))
	require.Equal(t, "application/json", rec.ResponseHdrs["Content-Type"])
	require.Equal(t, "abc123hash", rec.PayloadHash)
	require.Equal(t, tenantID.String(), rec.TenantID)
}

func TestRedisStoreCrossTenantIsolation(t *testing.T) {
	client := newFakeUniversalClient()
	store := NewRedisStore(client, time.Hour)
	ctx := context.Background()

	tenantA := uuid.New()
	tenantB := uuid.New()
	idemKey := "shared-key-1234"

	skA := storeKey(tenantA, idemKey)
	skB := storeKey(tenantB, idemKey)

	// Tenant A creates IN_PROGRESS.
	err := store.SetInProgress(ctx, skA, tenantA.String(), "hash-a")
	require.NoError(t, err)

	// Tenant B can still create their own IN_PROGRESS for the same idempotency key.
	err = store.SetInProgress(ctx, skB, tenantB.String(), "hash-b")
	require.NoError(t, err)

	// Tenant A's record should not be affected.
	recA, err := store.Get(ctx, skA)
	require.NoError(t, err)
	require.Equal(t, tenantA.String(), recA.TenantID)
	require.Equal(t, StatusInProgress, recA.Status)

	// Tenant B's record should be independent.
	recB, err := store.Get(ctx, skB)
	require.NoError(t, err)
	require.Equal(t, tenantB.String(), recB.TenantID)
	require.Equal(t, StatusInProgress, recB.Status)
}

func TestNewRedisStoreDefaultTTL(t *testing.T) {
	store := NewRedisStore(newFakeUniversalClient(), 0)
	require.Equal(t, defaultTTL, store.ttl)

	store = NewRedisStore(newFakeUniversalClient(), -1)
	require.Equal(t, defaultTTL, store.ttl)

	store = NewRedisStore(newFakeUniversalClient(), 2*time.Hour)
	require.Equal(t, 2*time.Hour, store.ttl)
}

func TestSha256HexDeterministic(t *testing.T) {
	h1 := sha256Hex([]byte("hello"))
	h2 := sha256Hex([]byte("hello"))
	require.Equal(t, h1, h2)
	require.Len(t, h1, 64) // SHA-256 hex = 64 chars

	h3 := sha256Hex([]byte("world"))
	require.NotEqual(t, h1, h3)
}

var _ = errors.Is
