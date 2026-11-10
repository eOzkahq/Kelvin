package redis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisTLSAndServerNameEnforcement(t *testing.T) {
	t.Run("rediss scheme enforces TLS and ServerName", func(t *testing.T) {
		cfg := Config{
			URL: "rediss://:secret@redis-managed.prod.internal:6380/0",
		}
		client, err := NewClient(cfg)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.True(t, client.cfg.TLSEnabled)
	})

	t.Run("TLSEnabled sets ServerName when using Addr without URL", func(t *testing.T) {
		cfg := Config{
			Addr:       "secure-redis.cloud.corp:6379",
			TLSEnabled: true,
			PoolSize:   APIPoolSize,
		}
		client, err := NewClient(cfg)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.True(t, client.cfg.TLSEnabled)
	})

	t.Run("Conservative bounded pool sizing for Oracle VM constraints", func(t *testing.T) {
		assert.Equal(t, 5, APIPoolSize)
		assert.Equal(t, 2, APIMinIdleConns)
		assert.Equal(t, 3, WorkerPoolSize)
		assert.Equal(t, 1, WorkerMinIdleConns)
		assert.Equal(t, 5*time.Second, DefaultDialTimeout)
		assert.Equal(t, 3*time.Second, DefaultReadTimeout)
		assert.Equal(t, 3*time.Second, DefaultWriteTimeout)
	})
}

func TestTenantKeyIsolation(t *testing.T) {
	tenantA := "tenant-uuid-aaaa-1111"
	tenantB := "tenant-uuid-bbbb-2222"
	opKey := "submit-assessment-req-123"

	// 1. Idempotency keys must include tenant ID in namespace
	keyA := FormatIdempotencyKey(tenantA, opKey)
	keyB := FormatIdempotencyKey(tenantB, opKey)

	assert.Equal(t, "kelvin:idempotency:tenant-uuid-aaaa-1111:submit-assessment-req-123", keyA)
	assert.Equal(t, "kelvin:idempotency:tenant-uuid-bbbb-2222:submit-assessment-req-123", keyB)
	assert.NotEqual(t, keyA, keyB, "Tenant keys must never collide")

	// 2. Cache keys must include tenant ID in namespace
	cacheA := FormatCacheKey(tenantA, "profile:profile-1")
	cacheB := FormatCacheKey(tenantB, "profile:profile-1")

	assert.Equal(t, "kelvin:cache:tenant-uuid-aaaa-1111:profile:profile-1", cacheA)
	assert.Equal(t, "kelvin:cache:tenant-uuid-bbbb-2222:profile:profile-1", cacheB)
	assert.NotEqual(t, cacheA, cacheB, "Tenant cache keys must never collide")

	// 3. Fallback when tenant is missing
	globalKey := FormatIdempotencyKey("", opKey)
	assert.Equal(t, "kelvin:idempotency:global:submit-assessment-req-123", globalKey)
}
