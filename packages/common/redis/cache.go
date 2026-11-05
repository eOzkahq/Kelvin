package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// FormatTenantKey constructs a strictly namespaced Redis key scoped to a tenant.
// Format: kelvin:{tenant_id}:{resource}:{id}
func FormatTenantKey(tenantID, resource, id string) string {
	if tenantID == "" {
		tenantID = "global"
	}
	if resource == "" {
		resource = "default"
	}
	if id == "" {
		return fmt.Sprintf("kelvin:%s:%s", tenantID, resource)
	}
	return fmt.Sprintf("kelvin:%s:%s:%s", tenantID, resource, id)
}

// ValidateTenantKey verifies that a Redis key is prefixed with the specified tenant ID.
func ValidateTenantKey(key, expectedTenantID string) bool {
	prefix := fmt.Sprintf("kelvin:%s:", expectedTenantID)
	return strings.HasPrefix(key, prefix)
}

// IdempotencyStore manages deterministic duplicate submission prevention.
type IdempotencyStore struct {
	client redis.UniversalClient
	prefix string
}

// NewIdempotencyStore initializes an IdempotencyStore.
func NewIdempotencyStore(client redis.UniversalClient, prefix string) *IdempotencyStore {
	if prefix == "" {
		prefix = "idempotency"
	}
	return &IdempotencyStore{
		client: client,
		prefix: prefix,
	}
}

// CheckOrSet verifies if an idempotency key has already been seen for the tenant.
// If not seen, it atomically claims it with the given TTL and returns isNew = true.
// If already seen, returns isNew = false without error.
func (s *IdempotencyStore) CheckOrSet(ctx context.Context, tenantID, key string, ttl time.Duration) (bool, error) {
	if tenantID == "" || key == "" {
		return false, errors.New("redis: tenantID and key cannot be empty")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	redisKey := FormatTenantKey(tenantID, s.prefix, key)
	isNew, err := s.client.SetNX(ctx, redisKey, "PROCESSED", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis: idempotency check error: %w", err)
	}
	return isNew, nil
}

// RateLimiter manages tenant-aware fair-share rate limits using Redis atomic counters.
type RateLimiter struct {
	client redis.UniversalClient
}

// NewRateLimiter initializes a tenant RateLimiter.
func NewRateLimiter(client redis.UniversalClient) *RateLimiter {
	return &RateLimiter{client: client}
}

// AllowRequest checks whether a tenant has exceeded their request limit within the sliding/fixed window.
// Returns (allowed, remaining, err).
func (rl *RateLimiter) AllowRequest(ctx context.Context, tenantID, action string, limit int64, window time.Duration) (bool, int64, error) {
	if tenantID == "" || action == "" {
		return false, 0, errors.New("redis: tenantID and action cannot be empty")
	}
	if limit <= 0 {
		return false, 0, errors.New("redis: limit must be positive")
	}

	windowBucket := time.Now().Unix() / int64(window.Seconds())
	key := FormatTenantKey(tenantID, "ratelimit", fmt.Sprintf("%s:%d", action, windowBucket))

	pipe := rl.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window+10*time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("redis: rate limiter error: %w", err)
	}

	count := incr.Val()
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return count <= limit, remaining, nil
}
