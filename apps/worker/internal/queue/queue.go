package queue

import (
	"context"
	"sync"
	"time"
)

// Job is one unit of scanner work dispatched by the control plane
// (ADR-0003: Redis broker; database remains job-state source of truth).
type Job struct {
	ID            string
	AssessmentID  string
	TenantID      string
	CorrelationID string
	Type          string
	Payload       []byte
}

// Queue is the worker-side abstraction over the job broker. Implementations:
// NopQueue (skeleton, Phase 1) and the Redis-backed queue (Phase 2).
type Queue interface {
	// Dequeue blocks until a job arrives or ctx is done.
	Dequeue(ctx context.Context) (Job, error)
	Complete(ctx context.Context, job Job) error
	Fail(ctx context.Context, job Job, reason string) error
}

// NopQueue never yields jobs; Dequeue waits for cancellation. It keeps the
// daemon runnable without a broker during Phase 1 scaffolding.
type NopQueue struct{}

// Dequeue blocks until ctx is done and returns ctx.Err().
func (NopQueue) Dequeue(ctx context.Context) (Job, error) {
	<-ctx.Done()
	return Job{}, ctx.Err()
}

// Complete is a no-op.
func (NopQueue) Complete(context.Context, Job) error { return nil }

// Fail is a no-op.
func (NopQueue) Fail(context.Context, Job, string) error { return nil }

// MemoryQueue is an in-process queue used by daemon unit tests and local
// wiring experiments; it is not a durable broker.
type MemoryQueue struct {
	mu   sync.Mutex
	jobs []Job
	ch   chan struct{}
}

// NewMemoryQueue builds an empty in-process queue.
func NewMemoryQueue() *MemoryQueue {
	return &MemoryQueue{ch: make(chan struct{}, 64)}
}

// Push enqueues a job and wakes one waiter.
func (m *MemoryQueue) Push(job Job) {
	m.mu.Lock()
	m.jobs = append(m.jobs, job)
	m.mu.Unlock()
	select {
	case m.ch <- struct{}{}:
	default:
	}
}

// Dequeue blocks until a job is pushed or ctx is done.
func (m *MemoryQueue) Dequeue(ctx context.Context) (Job, error) {
	for {
		m.mu.Lock()
		if len(m.jobs) > 0 {
			job := m.jobs[0]
			m.jobs = m.jobs[1:]
			m.mu.Unlock()
			return job, nil
		}
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return Job{}, ctx.Err()
		case <-m.ch:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Complete discards the job.
func (m *MemoryQueue) Complete(context.Context, Job) error { return nil }

// Fail discards the job.
func (m *MemoryQueue) Fail(context.Context, Job, string) error { return nil }
