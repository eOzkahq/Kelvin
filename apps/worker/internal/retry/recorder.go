package retry

import (
	"sync"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/classification"
)

// RetryEvent captures diagnostic details of an execution retry attempt.
type RetryEvent struct {
	JobID           string                           `json:"job_id"`
	Scanner         string                           `json:"scanner"`
	Target          string                           `json:"target"`
	Attempt         int                              `json:"attempt"`
	Failure         classification.ClassifiedFailure `json:"failure"`
	BackoffDuration time.Duration                    `json:"backoff_duration"`
	Timestamp       time.Time                        `json:"timestamp"`
}

// Listener is invoked whenever a retry attempt is scheduled.
type Listener func(event RetryEvent)

// Recorder tracks and broadcasts retry telemetry across job executions.
type Recorder struct {
	mu        sync.RWMutex
	events    []RetryEvent
	listeners []Listener
}

// NewRecorder instantiates an in-memory retry event recorder.
func NewRecorder() *Recorder {
	return &Recorder{
		events: make([]RetryEvent, 0),
	}
}

// Record appends a retry event and notifies registered listeners.
func (r *Recorder) Record(event RetryEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	r.mu.Lock()
	r.events = append(r.events, event)
	listeners := append([]Listener(nil), r.listeners...)
	r.mu.Unlock()

	for _, l := range listeners {
		l(event)
	}
}

// AddListener registers a callback for retry events.
func (r *Recorder) AddListener(l Listener) {
	if l == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = append(r.listeners, l)
}

// Events returns a snapshot copy of all recorded retry events.
func (r *Recorder) Events() []RetryEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	copied := make([]RetryEvent, len(r.events))
	copy(copied, r.events)
	return copied
}

// EventsForJob filters retry events for a specific job ID.
func (r *Recorder) EventsForJob(jobID string) []RetryEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matched []RetryEvent
	for _, ev := range r.events {
		if ev.JobID == jobID {
			matched = append(matched, ev)
		}
	}
	return matched
}
