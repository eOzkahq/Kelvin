package progress

import (
	"context"
	"sync"
	"time"
)

// ProgressEvent represents an auditable progress observation emitted to event streams.
type ProgressEvent struct {
	EventID      string            `json:"event_id"`
	AssessmentID string            `json:"assessment_id"`
	JobID        string            `json:"job_id"`
	TenantID     string            `json:"tenant_id"`
	Scanner      string            `json:"scanner,omitempty"`
	Stage        Stage             `json:"stage"`
	StageStatus  StageStatus       `json:"stage_status"`
	Progress     *ScannerProgress  `json:"progress,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Transitions  []StageTransition `json:"transitions,omitempty"`
}

// Publisher is the contract for streaming progress events into the platform lifecycle.
type Publisher interface {
	PublishProgress(ctx context.Context, event ProgressEvent) error
}

// NopPublisher silently drops all progress events.
type NopPublisher struct{}

// NewNopPublisher builds a NopPublisher.
func NewNopPublisher() NopPublisher {
	return NopPublisher{}
}

// PublishProgress is a no-op.
func (NopPublisher) PublishProgress(context.Context, ProgressEvent) error {
	return nil
}

// MemoryPublisher collects progress events in memory for testing and local verification.
type MemoryPublisher struct {
	mu     sync.RWMutex
	events []ProgressEvent
}

// NewMemoryPublisher builds an empty in-process memory publisher.
func NewMemoryPublisher() *MemoryPublisher {
	return &MemoryPublisher{
		events: make([]ProgressEvent, 0),
	}
}

// PublishProgress records the event in memory.
func (m *MemoryPublisher) PublishProgress(_ context.Context, event ProgressEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

// Events returns a copy of all published events.
func (m *MemoryPublisher) Events() []ProgressEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]ProgressEvent, len(m.events))
	copy(copied, m.events)
	return copied
}

// EventsForJob returns all events recorded for a specific job ID.
func (m *MemoryPublisher) EventsForJob(jobID string) []ProgressEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matched []ProgressEvent
	for _, ev := range m.events {
		if ev.JobID == jobID {
			matched = append(matched, ev)
		}
	}
	return matched
}

// Clear removes all recorded events.
func (m *MemoryPublisher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]ProgressEvent, 0)
}

// MultiPublisher fans out events across multiple downstream publishers.
type MultiPublisher struct {
	publishers []Publisher
}

// NewMultiPublisher constructs a composite publisher.
func NewMultiPublisher(pubs ...Publisher) Publisher {
	valid := make([]Publisher, 0, len(pubs))
	for _, p := range pubs {
		if p != nil {
			valid = append(valid, p)
		}
	}
	return &MultiPublisher{publishers: valid}
}

// PublishProgress fans out the event to all registered publishers.
func (m *MultiPublisher) PublishProgress(ctx context.Context, event ProgressEvent) error {
	for _, p := range m.publishers {
		if err := p.PublishProgress(ctx, event); err != nil {
			return err
		}
	}
	return nil
}
