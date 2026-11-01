package queue

import (
	"context"
	"errors"
	"sync"
	"time"

	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/apps/worker/internal/progress"
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
	WorkerToken   string
	DeliveryID    string
	Attempts      int
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
	mu             sync.Mutex
	jobs           []Job
	status         map[string]commonqueue.Status
	cancelled      map[string]bool
	progressEvents map[string][]progress.ProgressEvent
	ch             chan struct{}
}

// RedisQueue adapts the shared backend-neutral queue to the worker daemon API.
type RedisQueue struct {
	Queue      commonqueue.IJobQueue
	WorkerID   string
	mu         sync.Mutex
	deliveries map[string]commonqueue.Delivery
}

func NewRedisQueue(q commonqueue.IJobQueue, workerID string) (*RedisQueue, error) {
	if q == nil || workerID == "" {
		return nil, errors.New("worker queue requires a queue and worker ID")
	}
	return &RedisQueue{Queue: q, WorkerID: workerID, deliveries: map[string]commonqueue.Delivery{}}, nil
}
func (r *RedisQueue) Enqueue(ctx context.Context, j Job) error {
	return r.Queue.Enqueue(ctx, commonqueue.Message{Version: 1, ID: j.ID, AssessmentID: j.AssessmentID, TenantID: j.TenantID, CorrelationID: j.CorrelationID, Type: j.Type, Payload: j.Payload})
}
func (r *RedisQueue) Dequeue(ctx context.Context) (Job, error) {
	d, err := r.Queue.Consume(ctx, r.WorkerID)
	if err != nil {
		return Job{}, err
	}
	r.mu.Lock()
	r.deliveries[d.Message.ID] = d
	r.mu.Unlock()
	return Job{ID: d.Message.ID, AssessmentID: d.Message.AssessmentID, TenantID: d.Message.TenantID, CorrelationID: d.Message.CorrelationID, Type: d.Message.Type, Payload: d.Message.Payload, WorkerToken: d.Message.WorkerToken, DeliveryID: d.DeliveryID, Attempts: d.Attempts}, nil
}
func (r *RedisQueue) Complete(ctx context.Context, j Job) error {
	d, ok := r.delivery(j)
	if !ok {
		return errors.New("queue delivery not found")
	}
	if err := r.Queue.Complete(ctx, d); err != nil {
		return err
	}
	r.forget(j.ID)
	return nil
}
func (r *RedisQueue) Fail(ctx context.Context, j Job, reason string) error {
	d, ok := r.delivery(j)
	if !ok {
		return errors.New("queue delivery not found")
	}
	if err := r.Queue.Fail(ctx, d, errors.New(reason)); err != nil {
		return err
	}
	r.forget(j.ID)
	return nil
}
func (r *RedisQueue) delivery(j Job) (commonqueue.Delivery, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deliveries[j.ID]
	if ok {
		if j.DeliveryID != "" {
			d.DeliveryID = j.DeliveryID
		}
		if j.Attempts > 0 {
			d.Attempts = j.Attempts
		}
	}
	return d, ok
}
func (r *RedisQueue) forget(id string)                            { r.mu.Lock(); delete(r.deliveries, id); r.mu.Unlock() }
func (r *RedisQueue) Cancel(ctx context.Context, id string) error { return r.Queue.Cancel(ctx, id) }
func (r *RedisQueue) GetStatus(ctx context.Context, id string) (commonqueue.Status, error) {
	return r.Queue.GetStatus(ctx, id)
}
func (r *RedisQueue) Heartbeat(ctx context.Context, id, worker string, ttl time.Duration) error {
	return r.Queue.Heartbeat(ctx, id, worker, ttl)
}

// NewMemoryQueue builds an empty in-process queue.
func NewMemoryQueue() *MemoryQueue {
	return &MemoryQueue{
		ch:             make(chan struct{}, 64),
		status:         make(map[string]commonqueue.Status),
		cancelled:      make(map[string]bool),
		progressEvents: make(map[string][]progress.ProgressEvent),
	}
}

// PublishProgress records a progress event in memory.
func (m *MemoryQueue) PublishProgress(_ context.Context, ev progress.ProgressEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progressEvents[ev.JobID] = append(m.progressEvents[ev.JobID], ev)
	return nil
}

// GetProgressEvents returns all progress events recorded for a job.
func (m *MemoryQueue) GetProgressEvents(jobID string) []progress.ProgressEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	evs := m.progressEvents[jobID]
	copied := make([]progress.ProgressEvent, len(evs))
	copy(copied, evs)
	return copied
}

// Push enqueues a job and wakes one waiter.
func (m *MemoryQueue) Push(job Job) {
	m.mu.Lock()
	m.jobs = append(m.jobs, job)
	m.status[job.ID] = commonqueue.Status{State: "RUNNING", UpdatedAt: time.Now().UTC()}
	m.mu.Unlock()
	select {
	case m.ch <- struct{}{}:
	default:
	}
}

// Cancel marks a job as cancelled in memory.
func (m *MemoryQueue) Cancel(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelled[id] = true
	s := m.status[id]
	s.State = "CANCELLED"
	s.UpdatedAt = time.Now().UTC()
	m.status[id] = s
	return nil
}

// GetStatus retrieves the status of a job.
func (m *MemoryQueue) GetStatus(_ context.Context, id string) (commonqueue.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancelled[id] {
		return commonqueue.Status{State: "CANCELLED"}, nil
	}
	s, ok := m.status[id]
	if !ok {
		return commonqueue.Status{State: "RUNNING"}, nil
	}
	return s, nil
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
