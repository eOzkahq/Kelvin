package concurrency

import (
	"context"
	"time"
)

// Tier identifies which level of concurrency constraint was reached.
type Tier string

const (
	TierGlobal  Tier = "global"
	TierTenant  Tier = "tenant"
	TierScanner Tier = "scanner"
)

// SaturationInfo reports the active slots versus capacity for a specific tier.
type SaturationInfo struct {
	Tier            Tier    `json:"tier"`
	Active          int     `json:"active"`
	Capacity        int     `json:"capacity"`
	SaturationRatio float64 `json:"saturation_ratio"` // 0.0 - 1.0 (or >1.0 if oversubscribed)
}

// MetricsSnapshot provides a point-in-time view of concurrency usage and queue saturation.
type MetricsSnapshot struct {
	Timestamp      time.Time                 `json:"timestamp"`
	Global         SaturationInfo            `json:"global"`
	Tenants        map[string]SaturationInfo `json:"tenants"`
	Scanners       map[string]SaturationInfo `json:"scanners"`
	TotalAcquired  uint64                    `json:"total_acquired"`
	TotalReleased  uint64                    `json:"total_released"`
	TotalRejected  uint64                    `json:"total_rejected"`
	TotalReaped    uint64                    `json:"total_reaped"`
	TotalHeartbeat uint64                    `json:"total_heartbeat"`
}

// Controller coordinates multi-tiered execution slot acquisition, renewal, and release.
type Controller interface {
	// TryAcquire attempts to immediately acquire a concurrency slot without blocking.
	// Returns ErrCapacityUnavailable if any tier is saturated.
	TryAcquire(ctx context.Context, req Request) (Lease, error)

	// Acquire blocks until a concurrency slot becomes available or ctx/wait timeout expires.
	Acquire(ctx context.Context, req Request) (Lease, error)

	// Release returns an acquired slot back to the platform pool.
	Release(ctx context.Context, lease Lease) error

	// Heartbeat extends the lease expiration, preventing recovery sweepers from reclaiming slots.
	Heartbeat(ctx context.Context, lease Lease, extension time.Duration) error

	// Snapshot returns current active slots, limits, and saturation percentages across all tiers.
	Snapshot(ctx context.Context) (MetricsSnapshot, error)

	// ReapExpired scans for and reclaims slots whose TTL elapsed without a heartbeat (worker crash recovery).
	ReapExpired(ctx context.Context) (int, error)
}
