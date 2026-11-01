package egress

import (
	"sync"
	"time"
)

// ViolationEvent records an observable security violation when a scanner attempts
// unauthorized network egress (e.g. private RFC 1918 addresses, cloud metadata,
// out-of-scope targets, disallowed ports, or out-of-band callbacks).
type ViolationEvent struct {
	Timestamp            time.Time `json:"timestamp"`
	Scanner              string    `json:"scanner"`
	Target               string    `json:"target"`
	RequestedDestination string    `json:"requested_destination"`
	ResolvedIP           string    `json:"resolved_ip,omitempty"`
	Port                 int       `json:"port"`
	Protocol             string    `json:"protocol"`
	Reason               string    `json:"reason"`
}

// ViolationListener is a callback invoked synchronously or asynchronously when
// an egress policy violation occurs.
type ViolationListener func(ViolationEvent)

// ViolationBroadcaster coordinates observable violation events across listeners.
type ViolationBroadcaster struct {
	mu        sync.RWMutex
	listeners []ViolationListener
	events    []ViolationEvent
}

// NewViolationBroadcaster creates an empty broadcaster.
func NewViolationBroadcaster() *ViolationBroadcaster {
	return &ViolationBroadcaster{
		listeners: make([]ViolationListener, 0),
		events:    make([]ViolationEvent, 0),
	}
}

// AddListener registers a listener to be notified on egress violations.
func (b *ViolationBroadcaster) AddListener(l ViolationListener) {
	if l == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners = append(b.listeners, l)
}

// Record emits an event to all registered listeners and saves it in history.
func (b *ViolationBroadcaster) Record(event ViolationEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	b.mu.Lock()
	b.events = append(b.events, event)
	listeners := append([]ViolationListener(nil), b.listeners...)
	b.mu.Unlock()

	for _, l := range listeners {
		l(event)
	}
}

// Events returns a copy of all recorded violation events.
func (b *ViolationBroadcaster) Events() []ViolationEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]ViolationEvent, len(b.events))
	copy(copied, b.events)
	return copied
}

// Count returns the number of recorded violation events.
func (b *ViolationBroadcaster) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.events)
}

