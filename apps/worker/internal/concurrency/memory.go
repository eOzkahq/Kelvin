package concurrency

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MemoryController manages concurrency slots in-memory for a single worker node or unit test harness.
type MemoryController struct {
	mu     sync.Mutex
	policy Policy

	leases         map[string]Lease // keyed by LeaseID
	jobToLease     map[string]string
	globalActive   int
	tenantActive   map[string]int
	scannerActive  map[string]int

	notifyCh chan struct{}

	totalAcquired  uint64
	totalReleased  uint64
	totalRejected  uint64
	totalReaped    uint64
	totalHeartbeat uint64
}

// NewMemoryController constructs an in-memory concurrency controller configured with policy.
func NewMemoryController(p Policy) (*MemoryController, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &MemoryController{
		policy:        p,
		leases:        make(map[string]Lease),
		jobToLease:    make(map[string]string),
		tenantActive:  make(map[string]int),
		scannerActive: make(map[string]int),
		notifyCh:      make(chan struct{}, 1),
	}, nil
}

// TryAcquire attempts non-blocking slot acquisition across Global, Tenant, and Scanner tiers.
func (m *MemoryController) TryAcquire(ctx context.Context, req Request) (Lease, error) {
	if err := req.Validate(); err != nil {
		return Lease{}, err
	}
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Purge any expired leases before evaluating capacity
	m.reapExpiredLocked(time.Now().UTC())

	// 2. Check if this job already holds a lease (idempotency check)
	if existingLeaseID, ok := m.jobToLease[req.JobID]; ok {
		if lease, exists := m.leases[existingLeaseID]; exists {
			return lease, nil
		}
	}

	// 3. Evaluate multi-tier capacity
	// Tier 1: Global Limit
	if m.globalActive >= m.policy.GlobalLimit {
		m.totalRejected++
		return Lease{}, fmt.Errorf("%w: global limit of %d reached", ErrCapacityUnavailable, m.policy.GlobalLimit)
	}

	// Tier 2: Per-Tenant Limit
	if m.tenantActive[req.TenantID] >= m.policy.PerTenantLimit {
		m.totalRejected++
		return Lease{}, fmt.Errorf("%w: tenant %q reached limit of %d", ErrCapacityUnavailable, req.TenantID, m.policy.PerTenantLimit)
	}

	// Tier 3: Scanner-Specific Limit
	scannerLimit := m.policy.LimitForScanner(req.Scanner)
	if m.scannerActive[req.Scanner] >= scannerLimit {
		m.totalRejected++
		return Lease{}, fmt.Errorf("%w: scanner %q reached limit of %d", ErrCapacityUnavailable, req.Scanner, scannerLimit)
	}

	// 4. Capacity is available: claim slot
	ttl := req.TTL
	if ttl <= 0 {
		ttl = m.policy.DefaultLeaseTTL
	}
	lease := NewLease(req, ttl)

	m.leases[lease.LeaseID] = lease
	m.jobToLease[req.JobID] = lease.LeaseID
	m.globalActive++
	m.tenantActive[req.TenantID]++
	m.scannerActive[req.Scanner]++
	m.totalAcquired++

	return lease, nil
}

// Acquire blocks until a slot becomes available or ctx/WaitTimeout expires.
func (m *MemoryController) Acquire(ctx context.Context, req Request) (Lease, error) {
	timeout := m.policy.WaitTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		lease, err := m.TryAcquire(waitCtx, req)
		if err == nil {
			return lease, nil
		}
		if !errorsIsCapacity(err) {
			return Lease{}, err
		}

		// Wait for release notification or context cancellation
		select {
		case <-waitCtx.Done():
			return Lease{}, fmt.Errorf("%w: %v", ErrCapacityUnavailable, waitCtx.Err())
		case <-m.notifyCh:
			// Capacity was released; retry acquisition
		case <-time.After(50 * time.Millisecond):
			// Fallback polling tick
		}
	}
}

// Release relinquishes the concurrency slot and wakes pending waiters.
func (m *MemoryController) Release(_ context.Context, lease Lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, exists := m.leases[lease.LeaseID]
	if !exists {
		return nil // Idempotent release
	}

	delete(m.leases, lease.LeaseID)
	delete(m.jobToLease, stored.JobID)

	m.globalActive--
	if m.globalActive < 0 {
		m.globalActive = 0
	}

	m.tenantActive[stored.TenantID]--
	if m.tenantActive[stored.TenantID] <= 0 {
		delete(m.tenantActive, stored.TenantID)
	}

	m.scannerActive[stored.Scanner]--
	if m.scannerActive[stored.Scanner] <= 0 {
		delete(m.scannerActive, stored.Scanner)
	}

	m.totalReleased++
	m.signalWaiterLocked()
	return nil
}

// Heartbeat extends the lease expiration duration.
func (m *MemoryController) Heartbeat(_ context.Context, lease Lease, extension time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, exists := m.leases[lease.LeaseID]
	if !exists {
		return ErrLeaseNotFound
	}

	if extension <= 0 {
		extension = m.policy.DefaultLeaseTTL
	}
	stored.ExpiresAt = time.Now().UTC().Add(extension)
	m.leases[lease.LeaseID] = stored
	m.totalHeartbeat++
	return nil
}

// ReapExpired reclaims any slots held by crashed workers whose leases lapsed.
func (m *MemoryController) ReapExpired(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reapExpiredLocked(time.Now().UTC()), nil
}

func (m *MemoryController) reapExpiredLocked(now time.Time) int {
	reaped := 0
	for leaseID, lease := range m.leases {
		if lease.Expired(now) {
			delete(m.leases, leaseID)
			delete(m.jobToLease, lease.JobID)

			m.globalActive--
			if m.globalActive < 0 {
				m.globalActive = 0
			}

			m.tenantActive[lease.TenantID]--
			if m.tenantActive[lease.TenantID] <= 0 {
				delete(m.tenantActive, lease.TenantID)
			}

			m.scannerActive[lease.Scanner]--
			if m.scannerActive[lease.Scanner] <= 0 {
				delete(m.scannerActive, lease.Scanner)
			}

			reaped++
			m.totalReaped++
		}
	}
	if reaped > 0 {
		m.signalWaiterLocked()
	}
	return reaped
}

// Snapshot returns point-in-time concurrency and saturation metrics.
func (m *MemoryController) Snapshot(_ context.Context) (MetricsSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	globalRatio := 0.0
	if m.policy.GlobalLimit > 0 {
		globalRatio = float64(m.globalActive) / float64(m.policy.GlobalLimit)
	}

	tenants := make(map[string]SaturationInfo, len(m.tenantActive))
	for tID, count := range m.tenantActive {
		ratio := 0.0
		if m.policy.PerTenantLimit > 0 {
			ratio = float64(count) / float64(m.policy.PerTenantLimit)
		}
		tenants[tID] = SaturationInfo{
			Tier:            TierTenant,
			Active:          count,
			Capacity:        m.policy.PerTenantLimit,
			SaturationRatio: ratio,
		}
	}

	scanners := make(map[string]SaturationInfo, len(m.scannerActive))
	for sc, count := range m.scannerActive {
		limit := m.policy.LimitForScanner(sc)
		ratio := 0.0
		if limit > 0 {
			ratio = float64(count) / float64(limit)
		}
		scanners[sc] = SaturationInfo{
			Tier:            TierScanner,
			Active:          count,
			Capacity:        limit,
			SaturationRatio: ratio,
		}
	}

	return MetricsSnapshot{
		Timestamp: now,
		Global: SaturationInfo{
			Tier:            TierGlobal,
			Active:          m.globalActive,
			Capacity:        m.policy.GlobalLimit,
			SaturationRatio: globalRatio,
		},
		Tenants:        tenants,
		Scanners:       scanners,
		TotalAcquired:  m.totalAcquired,
		TotalReleased:  m.totalReleased,
		TotalRejected:  m.totalRejected,
		TotalReaped:    m.totalReaped,
		TotalHeartbeat: m.totalHeartbeat,
	}, nil
}

func (m *MemoryController) signalWaiterLocked() {
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
}

func errorsIsCapacity(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrCapacityUnavailable)
}
