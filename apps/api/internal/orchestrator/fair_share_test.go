package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFairShareScheduler_RoundRobinInterleaving(t *testing.T) {
	scheduler := NewFairShareScheduler()
	tenantA := uuid.New()
	tenantB := uuid.New()

	scheduler.SetTenantCapacity(tenantA, 5)
	scheduler.SetTenantCapacity(tenantB, 5)

	// Tenant A submits 4 jobs
	for i := 0; i < 4; i++ {
		err := scheduler.Enqueue(context.Background(), &WorkloadJob{
			TenantID: tenantA,
			JobType:  "SCAN",
			Priority: 5,
		})
		require.NoError(t, err)
	}

	// Tenant B submits 2 jobs
	for i := 0; i < 2; i++ {
		err := scheduler.Enqueue(context.Background(), &WorkloadJob{
			TenantID: tenantB,
			JobType:  "SCAN",
			Priority: 5,
		})
		require.NoError(t, err)
	}

	// Dispatch sequence should interleave between A and B
	job1, err := scheduler.DispatchNext(context.Background(), "worker-1")
	require.NoError(t, err)
	assert.Equal(t, tenantA, job1.TenantID)

	job2, err := scheduler.DispatchNext(context.Background(), "worker-2")
	require.NoError(t, err)
	assert.Equal(t, tenantB, job2.TenantID, "Tenant B must not starve behind Tenant A jobs")

	job3, err := scheduler.DispatchNext(context.Background(), "worker-3")
	require.NoError(t, err)
	assert.Equal(t, tenantA, job3.TenantID)

	job4, err := scheduler.DispatchNext(context.Background(), "worker-4")
	require.NoError(t, err)
	assert.Equal(t, tenantB, job4.TenantID)
}

func TestFairShareScheduler_TenantCapacityLimits(t *testing.T) {
	scheduler := NewFairShareScheduler()
	tenantA := uuid.New()
	tenantB := uuid.New()

	// Tenant A is restricted to 1 concurrent worker
	scheduler.SetTenantCapacity(tenantA, 1)
	scheduler.SetTenantCapacity(tenantB, 2)

	_ = scheduler.Enqueue(context.Background(), &WorkloadJob{TenantID: tenantA, JobType: "A1", Priority: 5})
	_ = scheduler.Enqueue(context.Background(), &WorkloadJob{TenantID: tenantA, JobType: "A2", Priority: 5})
	_ = scheduler.Enqueue(context.Background(), &WorkloadJob{TenantID: tenantB, JobType: "B1", Priority: 5})

	// Dispatch 1: Tenant A job
	j1, err := scheduler.DispatchNext(context.Background(), "w1")
	require.NoError(t, err)
	assert.Equal(t, tenantA, j1.TenantID)

	// Dispatch 2: Tenant A is at capacity (1/1 active). Must dispatch Tenant B!
	j2, err := scheduler.DispatchNext(context.Background(), "w2")
	require.NoError(t, err)
	assert.Equal(t, tenantB, j2.TenantID)

	// Dispatch 3: Tenant A still at capacity, Tenant B empty -> ErrNoEligibleJobs
	j3, err := scheduler.DispatchNext(context.Background(), "w3")
	assert.ErrorIs(t, err, ErrNoEligibleJobs)
	assert.Nil(t, j3)

	// Complete Tenant A job -> frees slot
	scheduler.CompleteJob(tenantA)

	// Now Tenant A job A2 can be dispatched
	j4, err := scheduler.DispatchNext(context.Background(), "w4")
	require.NoError(t, err)
	assert.Equal(t, tenantA, j4.TenantID)
	assert.Equal(t, "A2", j4.JobType)
}

func TestFairShareScheduler_PriorityOrdering(t *testing.T) {
	scheduler := NewFairShareScheduler()
	tenantA := uuid.New()
	now := time.Now().UTC()

	// Enqueue low priority first
	_ = scheduler.Enqueue(context.Background(), &WorkloadJob{
		TenantID:   tenantA,
		JobType:    "LOW_PRIORITY",
		Priority:   8,
		EnqueuedAt: now,
	})

	// Enqueue high priority later
	_ = scheduler.Enqueue(context.Background(), &WorkloadJob{
		TenantID:   tenantA,
		JobType:    "URGENT",
		Priority:   1, // Highest priority
		EnqueuedAt: now.Add(5 * time.Second),
	})

	job, err := scheduler.DispatchNext(context.Background(), "w-1")
	require.NoError(t, err)
	assert.Equal(t, "URGENT", job.JobType, "Priority 1 must be dispatched ahead of Priority 8")
}

func TestFairShareScheduler_TenantBackpressure(t *testing.T) {
	scheduler := NewFairShareScheduler()
	tenantA := uuid.New()

	// Enqueue up to default capacity (20)
	for i := 0; i < DefaultMaxTenantQueueDepth; i++ {
		err := scheduler.Enqueue(context.Background(), &WorkloadJob{
			TenantID: tenantA,
			JobType:  "SCAN",
		})
		require.NoError(t, err)
	}

	// 21st job should be rejected with backpressure error
	err := scheduler.Enqueue(context.Background(), &WorkloadJob{
		TenantID: tenantA,
		JobType:  "SCAN",
	})
	assert.ErrorIs(t, err, ErrTenantQueueSaturated)

	metrics := scheduler.GetMetrics()
	assert.Equal(t, DefaultMaxTenantQueueDepth, metrics.TotalQueuedJobs)
	assert.Equal(t, 1, metrics.SaturatedTenantsCount)
}
