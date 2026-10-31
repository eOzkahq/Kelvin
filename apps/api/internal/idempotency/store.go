// Package idempotency provides duplicate-prevention for state-mutating API
// operations using the Idempotency-Key header (RFC-style idempotency).
//
// Records are keyed by (tenant_id, idempotency_key) to guarantee cross-tenant
// isolation: a key presented by Tenant A can never match a record created by
// Tenant B. Each record carries a SHA-256 hash of the request payload so that
// reuse of the same key with a different body is rejected with 422.
//
// Records expire after a configurable TTL (default 24 hours) so that clients
// can safely reuse keys after the retention window.
package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// defaultTTL is the default retention window for idempotency records.
const defaultTTL = 24 * time.Hour

// keyPrefix is the Redis key prefix for idempotency records.
const keyPrefix = "kelvin:idempotency"

// Status represents the lifecycle status of an idempotency record.
type Status string

const (
	// StatusInProgress means the request is currently being processed.
	StatusInProgress Status = "IN_PROGRESS"
	// StatusCompleted means the request has been processed and the response
	// body is cached for replay.
	StatusCompleted Status = "COMPLETED"
)

// Record is the serialized idempotency record stored in Redis.
type Record struct {
	Key          string            `json:"key"`
	TenantID     string            `json:"tenant_id"`
	Status       Status            `json:"status"`
	PayloadHash  string            `json:"payload_hash"`
	ResponseCode int               `json:"response_code"`
	ResponseBody []byte            `json:"response_body,omitempty"`
	ResponseHdrs map[string]string `json:"response_headers,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Store is the idempotency store interface. Implementations must be safe for
// concurrent use.
type Store interface {
	// Get returns the record for the given store key, or ErrNotFound if no
	// record exists.
	Get(ctx context.Context, key string) (*Record, error)
	// SetInProgress atomically creates an IN_PROGRESS record. Returns
	// ErrAlreadyExists if a record already exists for the key (use Redis SET
	// NX semantics).
	SetInProgress(ctx context.Context, key, tenantID, payloadHash string) error
	// SetCompleted transitions an existing IN_PROGRESS record to COMPLETED and
	// caches the response data for replay.
	SetCompleted(ctx context.Context, key string, statusCode int, body []byte, headers map[string]string) error
}

var (
	// ErrNotFound is returned when no idempotency record exists for a key.
	ErrNotFound = errors.New("idempotency: key not found")
	// ErrAlreadyExists is returned when SetInProgress is called on a key that
	// already has a record.
	ErrAlreadyExists = errors.New("idempotency: key already exists")
)

// RedisStore implements Store using Redis with automatic TTL expiration.
type RedisStore struct {
	client redis.UniversalClient
	ttl    time.Duration
}

// NewRedisStore creates a Redis-backed idempotency store. If ttl is zero or
// negative, the default 24-hour TTL is used.
func NewRedisStore(client redis.UniversalClient, ttl time.Duration) *RedisStore {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &RedisStore{client: client, ttl: ttl}
}

// storeKey builds the Redis key for a (tenant_id, idempotency_key) pair,
// guaranteeing cross-tenant isolation.
func storeKey(tenantID uuid.UUID, idempotencyKey string) string {
	return fmt.Sprintf("%s:%s:%s", keyPrefix, tenantID, idempotencyKey)
}

// sha256Hex returns the SHA-256 hash of data as a lowercase hex string.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Get retrieves an idempotency record by store key.
func (s *RedisStore) Get(ctx context.Context, key string) (*Record, error) {
	val, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("idempotency: get: %w", err)
	}
	var rec Record
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, fmt.Errorf("idempotency: unmarshal: %w", err)
	}
	return &rec, nil
}

// SetInProgress atomically creates an IN_PROGRESS record using Redis SET NX,
// so only one concurrent request can claim the key.
func (s *RedisStore) SetInProgress(ctx context.Context, key, tenantID, payloadHash string) error {
	now := time.Now().UTC()
	rec := Record{
		Key:         key,
		TenantID:    tenantID,
		Status:      StatusInProgress,
		PayloadHash: payloadHash,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("idempotency: marshal: %w", err)
	}
	set := s.client.SetNX(ctx, key, data, s.ttl)
	if err := set.Err(); err != nil {
		return fmt.Errorf("idempotency: set nx: %w", err)
	}
	if !set.Val() {
		return ErrAlreadyExists
	}
	return nil
}

// SetCompleted transitions an existing record to COMPLETED and caches the
// response data. Preserves tenant_id and payload_hash from the existing
// IN_PROGRESS record.
func (s *RedisStore) SetCompleted(ctx context.Context, key string, statusCode int, body []byte, headers map[string]string) error {
	now := time.Now().UTC()

	// Preserve tenant_id, payload_hash, and created_at from existing record.
	var tenantID, payloadHash string
	var createdAt time.Time
	existing, err := s.Get(ctx, key)
	switch {
	case err == nil:
		tenantID = existing.TenantID
		payloadHash = existing.PayloadHash
		createdAt = existing.CreatedAt
	case errors.Is(err, ErrNotFound):
		// Record may have expired; proceed with empty fields.
	default:
		return fmt.Errorf("idempotency: get existing: %w", err)
	}

	rec := Record{
		Key:          key,
		TenantID:     tenantID,
		Status:       StatusCompleted,
		PayloadHash:  payloadHash,
		ResponseCode: statusCode,
		ResponseBody: body,
		ResponseHdrs: headers,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("idempotency: marshal: %w", err)
	}
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		return fmt.Errorf("idempotency: set completed: %w", err)
	}
	return nil
}
