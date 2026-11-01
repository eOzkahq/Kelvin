// Package adapters defines the scanner adapter lifecycle contract and its
// thread-safe registry. Registry metadata is stable discovery data; execution
// state remains attached to jobs and output envelopes.
package adapters

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"
)

var (
	ErrAdapterNotFound    = errors.New("adapters: scanner not found")
	ErrAdapterUnavailable = errors.New("adapters: scanner unavailable")
	ErrDuplicateAdapter   = errors.New("adapters: duplicate scanner registration")
	ErrInvalidMetadata    = errors.New("adapters: invalid scanner metadata")
)

var scannerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

type Adapter interface {
	Name() string
}

type Executable interface {
	Adapter
	Execute(context.Context, Task) (Result, error)
}

type Availability string

const (
	AvailabilityRegistered  Availability = "REGISTERED"
	AvailabilityAvailable   Availability = "AVAILABLE"
	AvailabilityUnavailable Availability = "UNAVAILABLE"
)

// Metadata describes a registered adapter independently of any scan run.
type Metadata struct {
	ID                string       `json:"id"`
	DisplayName       string       `json:"display_name"`
	Version           string       `json:"version"`
	SupportedTargets  []string     `json:"supported_target_types"`
	Capabilities      Capabilities `json:"capabilities"`
	ConfigVersion     string       `json:"config_version"`
	Availability      Availability `json:"availability"`
	UnavailableReason string       `json:"unavailable_reason,omitempty"`
}

type AdapterFactory func() ScannerAdapter

type registryEntry struct {
	mu       sync.Mutex
	metadata Metadata
	factory  AdapterFactory
	adapter  ScannerAdapter
}

// Registry maps stable scanner identifiers to factories and verified adapter
// instances. The first successful initialization caches the singleton instance.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*registryEntry
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]*registryEntry)}
}

// Register preserves the convenient instance registration API. The adapter's
// own Name, Version, and Capabilities become immutable registry metadata.
func (r *Registry) Register(a ScannerAdapter) error {
	if isNilAdapter(a) {
		return fmt.Errorf("%w: adapter must not be nil", ErrInvalidMetadata)
	}
	caps := cloneCapabilities(a.Capabilities())
	return r.RegisterAdapter(Metadata{
		ID: a.Name(), DisplayName: a.Name(), Version: a.Version(),
		SupportedTargets: append([]string(nil), caps.SupportedTargetTypes...),
		Capabilities:     caps, ConfigVersion: ScannerConfigVersion,
	}, func() ScannerAdapter { return a })
}

// RegisterAdapter registers a factory and its discovery metadata. Duplicate
// IDs are rejected deterministically; factories are never invoked at register time.
func (r *Registry) RegisterAdapter(metadata Metadata, factory AdapterFactory) error {
	if r == nil || factory == nil {
		return fmt.Errorf("%w: registry and factory are required", ErrInvalidMetadata)
	}
	if !scannerIDPattern.MatchString(metadata.ID) || strings.TrimSpace(metadata.DisplayName) == "" || strings.TrimSpace(metadata.Version) == "" || strings.TrimSpace(metadata.ConfigVersion) == "" {
		return fmt.Errorf("%w: id, display_name, version, and config_version are required", ErrInvalidMetadata)
	}
	if len(metadata.SupportedTargets) == 0 {
		return fmt.Errorf("%w: supported target types are required", ErrInvalidMetadata)
	}
	metadata.Availability = AvailabilityRegistered
	metadata.UnavailableReason = ""
	if len(metadata.Capabilities.SupportedTargetTypes) == 0 {
		metadata.Capabilities.SupportedTargetTypes = append([]string(nil), metadata.SupportedTargets...)
	}
	if !reflect.DeepEqual(metadata.Capabilities.SupportedTargetTypes, metadata.SupportedTargets) {
		return fmt.Errorf("%w: supported target types disagree between metadata and capabilities", ErrInvalidMetadata)
	}
	metadata = cloneMetadata(metadata)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[metadata.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateAdapter, metadata.ID)
	}
	r.entries[metadata.ID] = &registryEntry{metadata: metadata, factory: factory}
	return nil
}

// Initialize constructs and initializes every registered adapter in sorted
// order. A failed adapter is marked unavailable while healthy entries remain
// discoverable; a canceled context aborts startup.
func (r *Registry) Initialize(ctx context.Context, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	for _, id := range r.Names() {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry, _ := r.entry(id)
		entry.mu.Lock()
		if entry.metadata.Availability == AvailabilityAvailable {
			entry.mu.Unlock()
			continue
		}
		adapter, err := instantiate(entry)
		if err == nil {
			err = initializeAdapter(adapter, ctx, logger)
		}
		if err != nil {
			entry.metadata.Availability = AvailabilityUnavailable
			entry.metadata.UnavailableReason = err.Error()
			entry.mu.Unlock()
			logger.Error("scanner adapter unavailable", zap.String("scanner_id", id), zap.Error(err))
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			continue
		}
		entry.metadata.Availability = AvailabilityAvailable
		entry.metadata.UnavailableReason = ""
		entry.mu.Unlock()
	}
	return nil
}

// GetAdapter returns only an initialized, healthy adapter. Unknown and
// unavailable identifiers produce distinct stable errors.
func (r *Registry) GetAdapter(id string) (ScannerAdapter, error) {
	entry, ok := r.entry(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAdapterNotFound, id)
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.metadata.Availability != AvailabilityAvailable || entry.adapter == nil {
		return nil, fmt.Errorf("%w: %s", ErrAdapterUnavailable, id)
	}
	return entry.adapter, nil
}

// Lookup returns an available adapter, retaining the worker's boolean lookup API.
func (r *Registry) Lookup(id string) (ScannerAdapter, bool) {
	a, err := r.GetAdapter(id)
	return a, err == nil
}

// LookupExecutable is retained for the assessment worker dispatcher.
func (r *Registry) LookupExecutable(id string) (ScannerAdapter, bool) { return r.Lookup(id) }

// Metadata returns a defensive copy of one entry's registry metadata, including
// unavailable status and reason when initialization failed.
func (r *Registry) Metadata(id string) (Metadata, bool) {
	entry, ok := r.entry(id)
	if !ok {
		return Metadata{}, false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return cloneMetadata(entry.metadata), true
}

// ListAvailable returns healthy scanners in deterministic ID order.
func (r *Registry) ListAvailable() []Metadata {
	var available []Metadata
	for _, id := range r.Names() {
		metadata, _ := r.Metadata(id)
		if metadata.Availability == AvailabilityAvailable {
			available = append(available, metadata)
		}
	}
	return available
}

// FindByCapability returns available scanners matching a capability flag,
// category, supported protocol, or target type (case-insensitive).
func (r *Registry) FindByCapability(capability string) []Metadata {
	query := strings.ToLower(strings.TrimSpace(capability))
	if query == "" {
		return nil
	}
	var matches []Metadata
	for _, metadata := range r.ListAvailable() {
		caps := metadata.Capabilities
		matched := containsFold(caps.CheckCategories, query) || containsFold(caps.Flags, query) || containsFold(caps.SupportedProtocols, query) || containsFold(metadata.SupportedTargets, query)
		switch query {
		case "passive", "passive_only":
			matched = matched || caps.PassiveOnly
		case "active", "active_scanning":
			matched = matched || caps.ActiveScanning
		case "network", "requires_network":
			matched = matched || caps.RequiresNetwork
		case "cancellation", "supports_cancellation":
			matched = matched || caps.SupportsCancel
		case "sandbox", "requires_sandbox":
			matched = matched || caps.RequiresSandbox
		}
		if matched {
			matches = append(matches, metadata)
		}
	}
	return matches
}

// Names lists all registered identifiers, including entries not yet healthy.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.entries))
	for id := range r.entries {
		names = append(names, id)
	}
	sort.Strings(names)
	return names
}

func (r *Registry) entry(id string) (*registryEntry, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	return e, ok
}

func instantiate(entry *registryEntry) (adapter ScannerAdapter, err error) {
	if entry.adapter != nil {
		return entry.adapter, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			adapter = nil
			err = fmt.Errorf("adapter factory panicked: %v", recovered)
		}
	}()
	adapter = entry.factory()
	if isNilAdapter(adapter) {
		return nil, fmt.Errorf("adapter factory returned nil")
	}
	if adapter.Name() != entry.metadata.ID || adapter.Version() != entry.metadata.Version || !reflect.DeepEqual(adapter.Capabilities(), entry.metadata.Capabilities) {
		return nil, fmt.Errorf("adapter factory metadata does not match registration for %q", entry.metadata.ID)
	}
	entry.adapter = adapter
	return adapter, nil
}

func initializeAdapter(adapter ScannerAdapter, ctx context.Context, logger *zap.Logger) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("adapter lifecycle panicked: %v", recovered)
		}
	}()
	if err = adapter.Initialize(ctx, logger); err != nil {
		return err
	}
	return adapter.Health(ctx)
}

func isNilAdapter(adapter ScannerAdapter) bool {
	if adapter == nil {
		return true
	}
	v := reflect.ValueOf(adapter)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func cloneCapabilities(c Capabilities) Capabilities {
	c.CheckCategories = append([]string(nil), c.CheckCategories...)
	c.Flags = append([]string(nil), c.Flags...)
	c.SupportedTargetTypes = append([]string(nil), c.SupportedTargetTypes...)
	c.SupportedProtocols = append([]string(nil), c.SupportedProtocols...)
	return c
}

func cloneMetadata(m Metadata) Metadata {
	m.SupportedTargets = append([]string(nil), m.SupportedTargets...)
	m.Capabilities = cloneCapabilities(m.Capabilities)
	return m
}

func containsFold(values []string, query string) bool {
	for _, value := range values {
		if strings.EqualFold(value, query) {
			return true
		}
	}
	return false
}
