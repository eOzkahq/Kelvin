package concurrency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisController manages distributed concurrency limits across multiple worker instances.
type RedisController struct {
	client redis.UniversalClient
	prefix string
	policy Policy
}

// NewRedisController constructs a Redis-backed distributed concurrency controller.
func NewRedisController(client redis.UniversalClient, prefix string, p Policy) (*RedisController, error) {
	if client == nil {
		return nil, errors.New("concurrency: redis client is required")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "kelvin:concurrency"
	}
	return &RedisController{
		client: client,
		prefix: prefix,
		policy: p,
	}, nil
}

// Lua script for atomic 3-tier acquisition:
// KEYS: [1]=global_zset, [2]=tenant_zset, [3]=scanner_zset, [4]=lease_key, [5]=job_key
// ARGV: [1]=now_ms, [2]=expire_ms, [3]=lease_id, [4]=job_id, [5]=global_limit, [6]=tenant_limit, [7]=scanner_limit, [8]=lease_json, [9]=ttl_seconds
var acquireLua = redis.NewScript(`
local global_key = KEYS[1]
local tenant_key = KEYS[2]
local scanner_key = KEYS[3]
local lease_key = KEYS[4]
local job_key = KEYS[5]

local now_ms = tonumber(ARGV[1])
local expire_ms = tonumber(ARGV[2])
local lease_id = ARGV[3]
local job_id = ARGV[4]
local global_limit = tonumber(ARGV[5])
local tenant_limit = tonumber(ARGV[6])
local scanner_limit = tonumber(ARGV[7])
local lease_json = ARGV[8]
local ttl_seconds = tonumber(ARGV[9])

-- 1. Check existing lease for idempotency
local existing = redis.call('GET', job_key)
if existing then
    return {1, existing}
end

-- 2. Purge expired leases from all tiers
redis.call('ZREMRANGEBYSCORE', global_key, '-inf', now_ms)
redis.call('ZREMRANGEBYSCORE', tenant_key, '-inf', now_ms)
redis.call('ZREMRANGEBYSCORE', scanner_key, '-inf', now_ms)

-- 3. Check capacity in all tiers
local global_count = redis.call('ZCARD', global_key)
if global_count >= global_limit then
    return {0, 'global'}
end

local tenant_count = redis.call('ZCARD', tenant_key)
if tenant_count >= tenant_limit then
    return {0, 'tenant'}
end

local scanner_count = redis.call('ZCARD', scanner_key)
if scanner_count >= scanner_limit then
    return {0, 'scanner'}
end

-- 4. Claim slots atomically
redis.call('ZADD', global_key, expire_ms, lease_id)
redis.call('ZADD', tenant_key, expire_ms, lease_id)
redis.call('ZADD', scanner_key, expire_ms, lease_id)
redis.call('SETEX', lease_key, ttl_seconds, lease_json)
redis.call('SETEX', job_key, ttl_seconds, lease_id)

return {1, lease_id}
`)

func (r *RedisController) TryAcquire(ctx context.Context, req Request) (Lease, error) {
	if err := req.Validate(); err != nil {
		return Lease{}, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = r.policy.DefaultLeaseTTL
	}
	lease := NewLease(req, ttl)
	leaseJSON, err := json.Marshal(lease)
	if err != nil {
		return Lease{}, fmt.Errorf("concurrency: marshal lease: %w", err)
	}

	now := time.Now().UTC()
	nowMS := now.UnixMilli()
	expireMS := lease.ExpiresAt.UnixMilli()
	ttlSeconds := int(ttl.Seconds()) + 5

	scannerLimit := r.policy.LimitForScanner(req.Scanner)

	keys := []string{
		fmt.Sprintf("%s:global", r.prefix),
		fmt.Sprintf("%s:tenant:%s", r.prefix, req.TenantID),
		fmt.Sprintf("%s:scanner:%s", r.prefix, req.Scanner),
		fmt.Sprintf("%s:lease:%s", r.prefix, lease.LeaseID),
		fmt.Sprintf("%s:job:%s", r.prefix, req.JobID),
	}

	args := []any{
		nowMS,
		expireMS,
		lease.LeaseID,
		req.JobID,
		r.policy.GlobalLimit,
		r.policy.PerTenantLimit,
		scannerLimit,
		string(leaseJSON),
		ttlSeconds,
	}

	res, err := acquireLua.Run(ctx, r.client, keys, args...).Slice()
	if err != nil {
		return Lease{}, fmt.Errorf("concurrency: redis acquire script failed: %w", err)
	}

	success, ok := res[0].(int64)
	if !ok || success != 1 {
		tier, _ := res[1].(string)
		return Lease{}, fmt.Errorf("%w: %s limit reached", ErrCapacityUnavailable, tier)
	}

	return lease, nil
}

func (r *RedisController) Acquire(ctx context.Context, req Request) (Lease, error) {
	timeout := r.policy.WaitTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		lease, err := r.TryAcquire(waitCtx, req)
		if err == nil {
			return lease, nil
		}
		if !errorsIsCapacity(err) {
			return Lease{}, err
		}

		select {
		case <-waitCtx.Done():
			return Lease{}, fmt.Errorf("%w: %v", ErrCapacityUnavailable, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (r *RedisController) Release(ctx context.Context, lease Lease) error {
	globalKey := fmt.Sprintf("%s:global", r.prefix)
	tenantKey := fmt.Sprintf("%s:tenant:%s", r.prefix, lease.TenantID)
	scannerKey := fmt.Sprintf("%s:scanner:%s", r.prefix, lease.Scanner)
	leaseKey := fmt.Sprintf("%s:lease:%s", r.prefix, lease.LeaseID)
	jobKey := fmt.Sprintf("%s:job:%s", r.prefix, lease.JobID)

	pipe := r.client.Pipeline()
	pipe.ZRem(ctx, globalKey, lease.LeaseID)
	pipe.ZRem(ctx, tenantKey, lease.LeaseID)
	pipe.ZRem(ctx, scannerKey, lease.LeaseID)
	pipe.Del(ctx, leaseKey, jobKey)

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisController) Heartbeat(ctx context.Context, lease Lease, extension time.Duration) error {
	if extension <= 0 {
		extension = r.policy.DefaultLeaseTTL
	}
	now := time.Now().UTC()
	expireMS := now.Add(extension).UnixMilli()
	ttlSeconds := int(extension.Seconds()) + 5

	globalKey := fmt.Sprintf("%s:global", r.prefix)
	tenantKey := fmt.Sprintf("%s:tenant:%s", r.prefix, lease.TenantID)
	scannerKey := fmt.Sprintf("%s:scanner:%s", r.prefix, lease.Scanner)
	leaseKey := fmt.Sprintf("%s:lease:%s", r.prefix, lease.LeaseID)
	jobKey := fmt.Sprintf("%s:job:%s", r.prefix, lease.JobID)

	pipe := r.client.Pipeline()
	pipe.ZAdd(ctx, globalKey, redis.Z{Score: float64(expireMS), Member: lease.LeaseID})
	pipe.ZAdd(ctx, tenantKey, redis.Z{Score: float64(expireMS), Member: lease.LeaseID})
	pipe.ZAdd(ctx, scannerKey, redis.Z{Score: float64(expireMS), Member: lease.LeaseID})
	pipe.Expire(ctx, leaseKey, time.Duration(ttlSeconds)*time.Second)
	pipe.Expire(ctx, jobKey, time.Duration(ttlSeconds)*time.Second)

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisController) ReapExpired(ctx context.Context) (int, error) {
	nowMS := fmt.Sprint(time.Now().UTC().UnixMilli())
	globalKey := fmt.Sprintf("%s:global", r.prefix)

	removed, err := r.client.ZRemRangeByScore(ctx, globalKey, "-inf", nowMS).Result()
	if err != nil {
		return 0, err
	}
	return int(removed), nil
}

func (r *RedisController) Snapshot(ctx context.Context) (MetricsSnapshot, error) {
	now := time.Now().UTC()
	nowMS := now.UnixMilli()
	globalKey := fmt.Sprintf("%s:global", r.prefix)

	// Clean expired up to now
	_ = r.client.ZRemRangeByScore(ctx, globalKey, "-inf", fmt.Sprint(nowMS)).Err()
	globalActive, err := r.client.ZCard(ctx, globalKey).Result()
	if err != nil {
		return MetricsSnapshot{}, err
	}

	globalRatio := 0.0
	if r.policy.GlobalLimit > 0 {
		globalRatio = float64(globalActive) / float64(r.policy.GlobalLimit)
	}

	return MetricsSnapshot{
		Timestamp: now,
		Global: SaturationInfo{
			Tier:            TierGlobal,
			Active:          int(globalActive),
			Capacity:        r.policy.GlobalLimit,
			SaturationRatio: globalRatio,
		},
		Tenants:  make(map[string]SaturationInfo),
		Scanners: make(map[string]SaturationInfo),
	}, nil
}
