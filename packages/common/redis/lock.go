package redis

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrLeaseNotHeld is returned when an attempt to renew or release a lease fails because the caller does not own it.
	ErrLeaseNotHeld = errors.New("redis: lease is not held by specified owner or has expired")
	// ErrLeaseConflict is returned when a lease is already held by another worker.
	ErrLeaseConflict = errors.New("redis: lease acquisition failed, key currently held by another worker")
)

// Lua script to atomically renew an existing lease only if the owner matches.
var renewLeaseLua = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("pexpire", KEYS[1], ARGV[2])
else
    return 0
end
`)

// Lua script to atomically release an existing lease only if the owner matches.
var releaseLeaseLua = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
`)

// LeaseManager coordinates distributed locks across worker instances using Redis.
type LeaseManager struct {
	client redis.UniversalClient
	prefix string
}

// NewLeaseManager creates a new LeaseManager instance.
func NewLeaseManager(client redis.UniversalClient, prefix string) *LeaseManager {
	if prefix == "" {
		prefix = "kelvin:lease"
	}
	return &LeaseManager{
		client: client,
		prefix: prefix,
	}
}

func (lm *LeaseManager) formatKey(resource string) string {
	return fmt.Sprintf("%s:%s", lm.prefix, resource)
}

// AcquireLease attempts to atomically acquire a lease for a resource.
func (lm *LeaseManager) AcquireLease(ctx context.Context, resource, owner string, ttl time.Duration) (bool, error) {
	if resource == "" || owner == "" {
		return false, errors.New("redis: resource and owner cannot be empty")
	}
	if ttl <= 0 {
		return false, errors.New("redis: lease ttl must be positive")
	}

	key := lm.formatKey(resource)
	ok, err := lm.client.SetNX(ctx, key, owner, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis: failed to acquire lease for %s: %w", resource, err)
	}
	return ok, nil
}

// RenewLease extends the TTL of an active lease if the caller is the registered owner.
func (lm *LeaseManager) RenewLease(ctx context.Context, resource, owner string, ttl time.Duration) (bool, error) {
	if resource == "" || owner == "" {
		return false, errors.New("redis: resource and owner cannot be empty")
	}
	key := lm.formatKey(resource)
	ttlMillis := ttl.Milliseconds()

	res, err := renewLeaseLua.Run(ctx, lm.client, []string{key}, owner, ttlMillis).Result()
	if err != nil {
		return false, fmt.Errorf("redis: renew lease script error for %s: %w", resource, err)
	}

	status, ok := res.(int64)
	if !ok || status != 1 {
		return false, ErrLeaseNotHeld
	}
	return true, nil
}

// ReleaseLease removes the lease if the caller is the registered owner.
func (lm *LeaseManager) ReleaseLease(ctx context.Context, resource, owner string) (bool, error) {
	if resource == "" || owner == "" {
		return false, errors.New("redis: resource and owner cannot be empty")
	}
	key := lm.formatKey(resource)

	res, err := releaseLeaseLua.Run(ctx, lm.client, []string{key}, owner).Result()
	if err != nil {
		return false, fmt.Errorf("redis: release lease script error for %s: %w", resource, err)
	}

	status, ok := res.(int64)
	if !ok || status != 1 {
		return false, ErrLeaseNotHeld
	}
	return true, nil
}

// GetLeaseOwner returns the current lease owner and remaining TTL.
func (lm *LeaseManager) GetLeaseOwner(ctx context.Context, resource string) (string, time.Duration, error) {
	key := lm.formatKey(resource)
	owner, err := lm.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}

	pttl, err := lm.client.PTTL(ctx, key).Result()
	if err != nil {
		return owner, 0, err
	}

	return owner, pttl, nil
}

// StartHeartbeat begins a background goroutine that renews the lease periodically until canceled.
func (lm *LeaseManager) StartHeartbeat(ctx context.Context, resource, owner string, ttl, interval time.Duration) (cancel func()) {
	hbCtx, hbCancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(hbCtx, 2*time.Second)
				_, _ = lm.RenewLease(renewCtx, resource, owner, ttl)
				renewCancel()
			}
		}
	}()

	return func() {
		hbCancel()
		wg.Wait()
	}
}
