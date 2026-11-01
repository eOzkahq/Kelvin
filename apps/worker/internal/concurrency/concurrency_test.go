package concurrency

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyValidation(t *testing.T) {
	valid := DefaultPolicy()
	if err := valid.Validate(); err != nil {
		t.Fatalf("DefaultPolicy validation failed: %v", err)
	}

	// Negative global limit
	invalidGlobal := valid
	invalidGlobal.GlobalLimit = 0
	if err := invalidGlobal.Validate(); err == nil {
		t.Fatal("expected error on GlobalLimit <= 0")
	}

	// Tenant limit > global limit
	invalidTenant := valid
	invalidTenant.PerTenantLimit = valid.GlobalLimit + 5
	if err := invalidTenant.Validate(); err == nil {
		t.Fatal("expected error on PerTenantLimit > GlobalLimit")
	}

	// Scanner limit > global limit
	invalidScanner := valid
	invalidScanner.ScannerLimits = map[string]int{"nuclei": valid.GlobalLimit + 2}
	if err := invalidScanner.Validate(); err == nil {
		t.Fatal("expected error on ScannerLimits > GlobalLimit")
	}

	// Zero lease TTL
	invalidTTL := valid
	invalidTTL.DefaultLeaseTTL = 0
	if err := invalidTTL.Validate(); err == nil {
		t.Fatal("expected error on DefaultLeaseTTL <= 0")
	}
}

func TestGlobalConcurrencyLimitEnforcement(t *testing.T) {
	policy := Policy{
		GlobalLimit:     3,
		PerTenantLimit:  3,
		ScannerLimits:   map[string]int{"nuclei": 3},
		DefaultLeaseTTL: time.Minute,
		WaitTimeout:     100 * time.Millisecond,
	}

	ctrl, err := NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Acquire up to limit
	l1, err := ctrl.TryAcquire(ctx, Request{JobID: "j1", TenantID: "t1", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("l1 acquire error: %v", err)
	}
	l2, err := ctrl.TryAcquire(ctx, Request{JobID: "j2", TenantID: "t2", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("l2 acquire error: %v", err)
	}
	l3, err := ctrl.TryAcquire(ctx, Request{JobID: "j3", TenantID: "t3", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("l3 acquire error: %v", err)
	}

	// Next acquisition must fail due to global limit
	_, err = ctrl.TryAcquire(ctx, Request{JobID: "j4", TenantID: "t4", Scanner: "nuclei"})
	if !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatalf("expected ErrCapacityUnavailable on global limit, got %v", err)
	}

	// Release l2
	if err := ctrl.Release(ctx, l2); err != nil {
		t.Fatalf("release l2 error: %v", err)
	}

	// Now j4 should acquire successfully
	l4, err := ctrl.TryAcquire(ctx, Request{JobID: "j4", TenantID: "t4", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("j4 acquire error: %v", err)
	}

	_ = ctrl.Release(ctx, l1)
	_ = ctrl.Release(ctx, l3)
	_ = ctrl.Release(ctx, l4)
}

func TestPerTenantConcurrencyLimitEnforcement(t *testing.T) {
	policy := Policy{
		GlobalLimit:     10,
		PerTenantLimit:  2,
		ScannerLimits:   map[string]int{"nuclei": 10},
		DefaultLeaseTTL: time.Minute,
		WaitTimeout:     100 * time.Millisecond,
	}

	ctrl, err := NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Tenant A acquires 2 slots
	l1, err := ctrl.TryAcquire(ctx, Request{JobID: "j1", TenantID: "tenant-A", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("l1 error: %v", err)
	}
	l2, err := ctrl.TryAcquire(ctx, Request{JobID: "j2", TenantID: "tenant-A", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("l2 error: %v", err)
	}

	// Tenant A attempts 3rd slot -> blocked
	_, err = ctrl.TryAcquire(ctx, Request{JobID: "j3", TenantID: "tenant-A", Scanner: "nuclei"})
	if !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatalf("expected ErrCapacityUnavailable for tenant-A, got %v", err)
	}

	// Tenant B should still be able to acquire slots
	lB, err := ctrl.TryAcquire(ctx, Request{JobID: "jB", TenantID: "tenant-B", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("tenant-B acquire error: %v", err)
	}

	_ = ctrl.Release(ctx, l1)
	_ = ctrl.Release(ctx, l2)
	_ = ctrl.Release(ctx, lB)
}

func TestScannerSpecificConcurrencyLimitEnforcement(t *testing.T) {
	policy := Policy{
		GlobalLimit:     10,
		PerTenantLimit:  5,
		ScannerLimits:   map[string]int{"zap-baseline": 1, "nuclei": 5},
		DefaultLeaseTTL: time.Minute,
		WaitTimeout:     100 * time.Millisecond,
	}

	ctrl, err := NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Acquire zap-baseline (limit 1)
	lZ1, err := ctrl.TryAcquire(ctx, Request{JobID: "z1", TenantID: "tenant-1", Scanner: "zap-baseline"})
	if err != nil {
		t.Fatalf("lZ1 error: %v", err)
	}

	// Second zap-baseline job from different tenant must be rejected
	_, err = ctrl.TryAcquire(ctx, Request{JobID: "z2", TenantID: "tenant-2", Scanner: "zap-baseline"})
	if !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatalf("expected ErrCapacityUnavailable for zap-baseline, got %v", err)
	}

	// But a nuclei scan should succeed
	lN, err := ctrl.TryAcquire(ctx, Request{JobID: "n1", TenantID: "tenant-2", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("nuclei error: %v", err)
	}

	_ = ctrl.Release(ctx, lZ1)
	_ = ctrl.Release(ctx, lN)
}

func TestConcurrentRaceConditionSafety(t *testing.T) {
	limit := 5
	policy := Policy{
		GlobalLimit:     limit,
		PerTenantLimit:  limit,
		DefaultLeaseTTL: time.Minute,
		WaitTimeout:     500 * time.Millisecond,
	}

	ctrl, err := NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	goroutines := 50
	var activeSlots int64
	var maxObserved int64
	var wg sync.WaitGroup

	ctx := context.Background()

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := Request{
				JobID:    fmt.Sprintf("job-%d", idx),
				TenantID: "tenant-concurrent",
				Scanner:  "nuclei",
			}
			lease, err := ctrl.Acquire(ctx, req)
			if err != nil {
				return // Timed out waiting
			}

			curr := atomic.AddInt64(&activeSlots, 1)
			for {
				oldMax := atomic.LoadInt64(&maxObserved)
				if curr <= oldMax || atomic.CompareAndSwapInt64(&maxObserved, oldMax, curr) {
					break
				}
			}

			// Simulated work
			time.Sleep(10 * time.Millisecond)

			atomic.AddInt64(&activeSlots, -1)
			_ = ctrl.Release(ctx, lease)
		}(i)
	}

	wg.Wait()

	if maxObserved > int64(limit) {
		t.Fatalf("max concurrent slots exceeded limit: observed %d, limit %d", maxObserved, limit)
	}

	snap, _ := ctrl.Snapshot(ctx)
	if snap.Global.Active != 0 {
		t.Fatalf("expected 0 active slots after all released, got %d", snap.Global.Active)
	}
}

func TestWorkerCrashRecoveryReapExpired(t *testing.T) {
	policy := Policy{
		GlobalLimit:     2,
		PerTenantLimit:  2,
		DefaultLeaseTTL: 25 * time.Millisecond, // very short TTL
		WaitTimeout:     100 * time.Millisecond,
	}

	ctrl, err := NewMemoryController(policy)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Fill capacity with short TTL
	_, _ = ctrl.TryAcquire(ctx, Request{JobID: "j1", TenantID: "t1", Scanner: "nuclei"})
	_, _ = ctrl.TryAcquire(ctx, Request{JobID: "j2", TenantID: "t2", Scanner: "nuclei"})

	// Capacity now full
	_, err = ctrl.TryAcquire(ctx, Request{JobID: "j3", TenantID: "t3", Scanner: "nuclei"})
	if !errors.Is(err, ErrCapacityUnavailable) {
		t.Fatal("expected capacity unavailable")
	}

	// Sleep past the lease TTL to simulate worker crash
	time.Sleep(40 * time.Millisecond)

	// Reap expired leases
	reaped, err := ctrl.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired error: %v", err)
	}
	if reaped != 2 {
		t.Fatalf("expected 2 reaped leases, got %d", reaped)
	}

	// Capacity must be available now
	l3, err := ctrl.TryAcquire(ctx, Request{JobID: "j3", TenantID: "t3", Scanner: "nuclei"})
	if err != nil {
		t.Fatalf("j3 acquire after reap error: %v", err)
	}
	_ = ctrl.Release(ctx, l3)
}

func TestSnapshotAndSaturationMetrics(t *testing.T) {
	policy := Policy{
		GlobalLimit:     4,
		PerTenantLimit:  2,
		ScannerLimits:   map[string]int{"nuclei": 2},
		DefaultLeaseTTL: time.Minute,
	}

	ctrl, _ := NewMemoryController(policy)
	ctx := context.Background()

	l1, _ := ctrl.TryAcquire(ctx, Request{JobID: "j1", TenantID: "tenant-A", Scanner: "nuclei"})
	l2, _ := ctrl.TryAcquire(ctx, Request{JobID: "j2", TenantID: "tenant-A", Scanner: "nuclei"})

	snap, err := ctrl.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Global: 2 active out of 4 (50% saturated)
	if snap.Global.Active != 2 || snap.Global.Capacity != 4 {
		t.Errorf("global active=%d, cap=%d", snap.Global.Active, snap.Global.Capacity)
	}
	if snap.Global.SaturationRatio != 0.50 {
		t.Errorf("global saturation ratio = %f, want 0.50", snap.Global.SaturationRatio)
	}

	// Tenant-A: 2 active out of 2 (100% saturated)
	tenantA := snap.Tenants["tenant-A"]
	if tenantA.Active != 2 || tenantA.Capacity != 2 {
		t.Errorf("tenant-A active=%d, cap=%d", tenantA.Active, tenantA.Capacity)
	}
	if tenantA.SaturationRatio != 1.0 {
		t.Errorf("tenant-A saturation ratio = %f, want 1.0", tenantA.SaturationRatio)
	}

	// Scanner nuclei: 2 active out of 2 (100% saturated)
	nuclei := snap.Scanners["nuclei"]
	if nuclei.Active != 2 || nuclei.Capacity != 2 {
		t.Errorf("nuclei active=%d, cap=%d", nuclei.Active, nuclei.Capacity)
	}
	if nuclei.SaturationRatio != 1.0 {
		t.Errorf("nuclei saturation ratio = %f, want 1.0", nuclei.SaturationRatio)
	}

	_ = ctrl.Release(ctx, l1)
	_ = ctrl.Release(ctx, l2)
}
