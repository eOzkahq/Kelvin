package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrTenantQueueSaturated = errors.New("orchestrator: tenant job queue is saturated (backpressure)")
	ErrGlobalBackpressure   = errors.New("orchestrator: global system capacity reached (backpressure)")
	ErrNoEligibleJobs       = errors.New("orchestrator: no eligible jobs ready for dispatch")
	ErrJobNotFound          = errors.New("orchestrator: job not found in execution tracking")
)

const (
	DefaultMaxTenantQueueDepth  = 20
	DefaultMaxGlobalQueueDepth  = 500
	DefaultMaxTenantConcurrency = 2
)

// WorkloadJob represents an asynchronous task scheduled for worker execution.
type WorkloadJob struct {
	ID         uuid.UUID      `json:"id"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	JobType    string         `json:"job_type"` // ASSESSMENT_SCAN, REPORT_COMPILE, INTEGRATION_SYNC
	Priority   int            `json:"priority"` // 1 (highest) to 10 (lowest)
	Payload    map[string]any `json:"payload,omitempty"`
	WorkerID   string         `json:"worker_id,omitempty"`
	EnqueuedAt time.Time      `json:"enqueued_at"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
}

// SchedulerMetrics provides visibility into queue depth and worker distribution.
type SchedulerMetrics struct {
	TotalQueuedJobs       int            `json:"total_queued_jobs"`
	ActiveWorkersTotal    int            `json:"active_workers_total"`
	PerTenantQueued       map[string]int `json:"per_tenant_queued"`
	PerTenantActive       map[string]int `json:"per_tenant_active"`
	SaturatedTenantsCount int            `json:"saturated_tenants_count"`
}

type tenantQueueState struct {
	jobs          []*WorkloadJob
	activeWorkers int
	maxWorkers    int
}

// FairShareScheduler coordinates fair-share round-robin job dispatch across tenant queues.
type FairShareScheduler struct {
	mu                   sync.Mutex
	tenantQueues         map[uuid.UUID]*tenantQueueState
	tenantOrder          []uuid.UUID
	lastTenantIndex      int
	maxTenantQueueDepth  int
	maxGlobalQueueDepth  int
	defaultMaxConcurrent int
}

func NewFairShareScheduler() *FairShareScheduler {
	return &FairShareScheduler{
		tenantQueues:         make(map[uuid.UUID]*tenantQueueState),
		tenantOrder:          make([]uuid.UUID, 0),
		lastTenantIndex:      -1,
		maxTenantQueueDepth:  DefaultMaxTenantQueueDepth,
		maxGlobalQueueDepth:  DefaultMaxGlobalQueueDepth,
		defaultMaxConcurrent: DefaultMaxTenantConcurrency,
	}
}

// SetTenantCapacity configures maximum concurrent worker slots for a tenant.
func (s *FairShareScheduler) SetTenantCapacity(tenantID uuid.UUID, maxConcurrent int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.tenantQueues[tenantID]
	if !ok {
		state = &tenantQueueState{
			jobs:       make([]*WorkloadJob, 0),
			maxWorkers: maxConcurrent,
		}
		s.tenantQueues[tenantID] = state
		s.tenantOrder = append(s.tenantOrder, tenantID)
	} else {
		state.maxWorkers = maxConcurrent
	}
}

// Enqueue submits a job into the tenant's isolated queue with backpressure checks.
func (s *FairShareScheduler) Enqueue(ctx context.Context, job *WorkloadJob) error {
	if job == nil || job.TenantID == uuid.Nil {
		return errors.New("orchestrator: invalid job or missing tenant id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check global backpressure
	totalQueued := 0
	for _, q := range s.tenantQueues {
		totalQueued += len(q.jobs)
	}
	if totalQueued >= s.maxGlobalQueueDepth {
		return ErrGlobalBackpressure
	}

	state, ok := s.tenantQueues[job.TenantID]
	if !ok {
		state = &tenantQueueState{
			jobs:       make([]*WorkloadJob, 0),
			maxWorkers: s.defaultMaxConcurrent,
		}
		s.tenantQueues[job.TenantID] = state
		s.tenantOrder = append(s.tenantOrder, job.TenantID)
	}

	// Check per-tenant backpressure
	if len(state.jobs) >= s.maxTenantQueueDepth {
		return fmt.Errorf("%w: tenant queue reached max capacity %d", ErrTenantQueueSaturated, s.maxTenantQueueDepth)
	}

	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	if job.EnqueuedAt.IsZero() {
		job.EnqueuedAt = time.Now().UTC()
	}
	if job.Priority <= 0 {
		job.Priority = 5
	}

	state.jobs = append(state.jobs, job)

	// Sort queue: Priority ASC (1 is highest), EnqueuedAt ASC
	sort.SliceStable(state.jobs, func(i, j int) bool {
		if state.jobs[i].Priority == state.jobs[j].Priority {
			return state.jobs[i].EnqueuedAt.Before(state.jobs[j].EnqueuedAt)
		}
		return state.jobs[i].Priority < state.jobs[j].Priority
	})

	return nil
}

// DispatchNext selects the next job using fair-share round-robin across tenant queues.
func (s *FairShareScheduler) DispatchNext(ctx context.Context, workerID string) (*WorkloadJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	numTenants := len(s.tenantOrder)
	if numTenants == 0 {
		return nil, ErrNoEligibleJobs
	}

	// Iterate in round-robin fashion starting from the next tenant
	for i := 0; i < numTenants; i++ {
		candidateIndex := (s.lastTenantIndex + 1 + i) % numTenants
		tenantID := s.tenantOrder[candidateIndex]
		state := s.tenantQueues[tenantID]

		// Skip empty queues
		if len(state.jobs) == 0 {
			continue
		}

		// Skip tenants currently at their concurrency limit
		if state.activeWorkers >= state.maxWorkers {
			continue
		}

		// Eligible job found
		job := state.jobs[0]
		state.jobs = state.jobs[1:]
		state.activeWorkers++

		now := time.Now().UTC()
		job.StartedAt = &now
		job.WorkerID = workerID

		s.lastTenantIndex = candidateIndex
		return job, nil
	}

	return nil, ErrNoEligibleJobs
}

// CompleteJob releases a worker slot for the specified tenant upon job termination.
func (s *FairShareScheduler) CompleteJob(tenantID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, ok := s.tenantQueues[tenantID]; ok {
		if state.activeWorkers > 0 {
			state.activeWorkers--
		}
	}
}

// GetMetrics returns real-time scheduler state and saturation counts.
func (s *FairShareScheduler) GetMetrics() SchedulerMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()

	metrics := SchedulerMetrics{
		PerTenantQueued: make(map[string]int),
		PerTenantActive: make(map[string]int),
	}

	for id, q := range s.tenantQueues {
		qLen := len(q.jobs)
		metrics.TotalQueuedJobs += qLen
		metrics.ActiveWorkersTotal += q.activeWorkers
		metrics.PerTenantQueued[id.String()] = qLen
		metrics.PerTenantActive[id.String()] = q.activeWorkers

		if qLen >= s.maxTenantQueueDepth {
			metrics.SaturatedTenantsCount++
		}
	}

	return metrics
}
