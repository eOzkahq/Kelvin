package governance

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuotaManager_ConcurrentScanLimits(t *testing.T) {
	mgr := NewQuotaManager()
	tenantID := uuid.New()

	err := mgr.SetQuota(TenantQuota{
		TenantID:             tenantID,
		MaxConcurrentScans:   2,
		MaxMonthlyScanHours:  50,
		MaxStorageGB:         20,
		MaxServiceIdentities: 10,
		MaxMonthlyEvents:     1000,
	})
	require.NoError(t, err)

	// Acquire 1st slot
	rel1, err := mgr.AcquireConcurrentScan(context.Background(), tenantID)
	require.NoError(t, err)
	require.NotNil(t, rel1)

	// Acquire 2nd slot
	rel2, err := mgr.AcquireConcurrentScan(context.Background(), tenantID)
	require.NoError(t, err)
	require.NotNil(t, rel2)

	// 3rd slot should be throttled (max = 2)
	rel3, err := mgr.AcquireConcurrentScan(context.Background(), tenantID)
	assert.ErrorIs(t, err, ErrQuotaExceeded)
	assert.Nil(t, rel3)

	var qErr *QuotaExceededError
	require.ErrorAs(t, err, &qErr)
	assert.Equal(t, DimConcurrentScans, qErr.Dimension)
	assert.Equal(t, 2.0, qErr.Limit)
	assert.Equal(t, 2.0, qErr.Current)

	// Release one slot
	rel1()

	// Release should be idempotent (calling again shouldn't decrement below 0)
	rel1()

	// Now 3rd slot should succeed
	rel3, err = mgr.AcquireConcurrentScan(context.Background(), tenantID)
	require.NoError(t, err)
	require.NotNil(t, rel3)

	rel2()
	rel3()
}

func TestQuotaManager_ConcurrencyRaceProtection(t *testing.T) {
	mgr := NewQuotaManager()
	tenantID := uuid.New()

	limit := 5
	err := mgr.SetQuota(TenantQuota{
		TenantID:             tenantID,
		MaxConcurrentScans:   limit,
		MaxMonthlyScanHours:  100,
		MaxStorageGB:         50,
		MaxServiceIdentities: 10,
		MaxMonthlyEvents:     5000,
	})
	require.NoError(t, err)

	var (
		wg           sync.WaitGroup
		successCount int64
		failureCount int64
		releases     []func()
		mu           sync.Mutex
	)

	// Launch 50 concurrent requests competing for 5 slots
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := mgr.AcquireConcurrentScan(context.Background(), tenantID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
				mu.Lock()
				releases = append(releases, rel)
				mu.Unlock()
			} else {
				atomic.AddInt64(&failureCount, 1)
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(limit), successCount, "Only exact limit slots should be acquired concurrently")
	assert.Equal(t, int64(45), failureCount, "All other requests should be throttled")

	// Clean up releases
	for _, rel := range releases {
		rel()
	}
}

func TestQuotaManager_DimensionUsageAndSummary(t *testing.T) {
	mgr := NewQuotaManager()
	tenantID := uuid.New()

	err := mgr.SetQuota(TenantQuota{
		TenantID:             tenantID,
		MaxConcurrentScans:   5,
		MaxMonthlyScanHours:  100,
		MaxStorageGB:         50,
		MaxServiceIdentities: 10,
		MaxMonthlyEvents:     1000,
	})
	require.NoError(t, err)

	// 1. Record 20 scan hours
	err = mgr.RecordUsage(context.Background(), tenantID, DimMonthlyScanHours, 20.0)
	require.NoError(t, err)

	// 2. Record 25 GB storage
	err = mgr.RecordUsage(context.Background(), tenantID, DimStorageGB, 25.0)
	require.NoError(t, err)

	// 3. Exceed storage quota (request 30 GB more when limit is 50, current is 25)
	err = mgr.RecordUsage(context.Background(), tenantID, DimStorageGB, 30.0)
	assert.ErrorIs(t, err, ErrQuotaExceeded)

	// 4. Check usage summary
	summary, err := mgr.GetUsageSummary(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Equal(t, 20.0, summary.ConsumedScanHours)
	assert.Equal(t, 25.0, summary.CurrentStorageGB)
	assert.Equal(t, 20.0, summary.PercentUtilized[DimMonthlyScanHours])
	assert.Equal(t, 50.0, summary.PercentUtilized[DimStorageGB])
}
