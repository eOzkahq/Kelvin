// Package adapter defines the central registry and capability discovery engine
// for all KELVIN scanner integrations.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Sentinel errors for registry operations.
var (
	ErrAdapterAlreadyRegistered = errors.New("registry: scanner adapter already registered")
	ErrAdapterNotFound          = errors.New("registry: scanner adapter not found")
	ErrInvalidRegistration     = errors.New("registry: invalid adapter registration")
)

// Registration contains discovery and capability metadata for a registered scanner adapter.
type Registration struct {
	ID                   string       `json:"id"`
	DisplayName          string       `json:"display_name"`
	Version              string       `json:"version"`
	SupportedTargetTypes []string     `json:"supported_target_types"`
	Capabilities         Capabilities `json:"capabilities"`
	ConfigVersion        string       `json:"config_version"`
	Availability         HealthState  `json:"availability"`
	RegisteredAt         time.Time    `json:"registered_at"`
}

// ScannerRegistry provides thread-safe discovery and resolution of scanner adapters.
type ScannerRegistry struct {
	mu       sync.RWMutex
	adapters map[string]ScannerAdapter
	metadata map[string]Registration
}

// NewScannerRegistry initializes an empty ScannerRegistry.
func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{
		adapters: make(map[string]ScannerAdapter),
		metadata: make(map[string]Registration),
	}
}

// Register adds a new adapter to the registry; returns ErrAdapterAlreadyRegistered on duplicate ID.
func (r *ScannerRegistry) Register(adapter ScannerAdapter, meta Registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if adapter == nil {
		return fmt.Errorf("%w: adapter implementation cannot be nil", ErrInvalidRegistration)
	}

	id := adapter.Name()
	if id == "" {
		return fmt.Errorf("%w: adapter name cannot be empty", ErrInvalidRegistration)
	}
	if meta.ID == "" {
		meta.ID = id
	} else if meta.ID != id {
		return fmt.Errorf("%w: registration ID %q does not match adapter name %q", ErrInvalidRegistration, meta.ID, id)
	}

	if meta.DisplayName == "" {
		meta.DisplayName = id
	}
	if meta.Version == "" {
		meta.Version = adapter.Version()
	}
	if meta.ConfigVersion == "" {
		meta.ConfigVersion = ConfigSchemaVersion
	}
	if meta.RegisteredAt.IsZero() {
		meta.RegisteredAt = time.Now()
	}
	meta.Capabilities = adapter.Capabilities()
	meta.Availability = HealthStateHealthy

	if _, exists := r.adapters[id]; exists {
		return fmt.Errorf("%w: %q", ErrAdapterAlreadyRegistered, id)
	}

	r.adapters[id] = adapter
	r.metadata[id] = meta
	return nil
}

// Lookup retrieves a registered adapter and its metadata by scanner ID.
func (r *ScannerRegistry) Lookup(id string) (ScannerAdapter, Registration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, ok := r.adapters[id]
	if !ok {
		return nil, Registration{}, fmt.Errorf("%w: %q", ErrAdapterNotFound, id)
	}
	return adapter, r.metadata[id], nil
}

// ListAvailable returns all registered adapter metadata sorted by ID.
func (r *ScannerRegistry) ListAvailable() []Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]Registration, 0, len(r.metadata))
	for _, m := range r.metadata {
		res = append(res, m)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})
	return res
}

// GetCapabilities returns the capabilities for a registered scanner ID.
func (r *ScannerRegistry) GetCapabilities(id string) (Capabilities, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	meta, ok := r.metadata[id]
	if !ok {
		return Capabilities{}, fmt.Errorf("%w: %q", ErrAdapterNotFound, id)
	}
	return meta.Capabilities, nil
}

// CheckAvailability queries the adapter's Health method and updates the registry state.
func (r *ScannerRegistry) CheckAvailability(ctx context.Context, id string) (HealthStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	adapter, ok := r.adapters[id]
	if !ok {
		return HealthStatus{}, fmt.Errorf("%w: %q", ErrAdapterNotFound, id)
	}

	status := adapter.Health(ctx)
	meta := r.metadata[id]
	meta.Availability = status.State
	r.metadata[id] = meta

	return status, nil
}
