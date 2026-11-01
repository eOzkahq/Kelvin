// Package adapters defines the scanner adapter lifecycle contract and registry.
//
// See docs/architecture/EXECUTION_ISOLATION.md §5 for the normative adapter
// contract: task ingestion, sandbox execution, and structured finding egress.
package adapters

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"go.uber.org/zap"
)

// Adapter is the identity shared by registered scanner implementations.
type Adapter interface {
	Name() string
}

// Executable is the execution subset of ScannerAdapter.
type Executable interface {
	Adapter
	Execute(context.Context, Task) (Result, error)
}

// Registry maps adapter names to implementations, built once at startup.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]ScannerAdapter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]ScannerAdapter)}
}

// Register adds an adapter; duplicate names are rejected.
func (r *Registry) Register(a ScannerAdapter) error {
	if a == nil {
		return fmt.Errorf("adapters: adapter must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	name := a.Name()
	if name == "" {
		return fmt.Errorf("adapters: adapter name must not be empty")
	}
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("adapters: %q already registered", name)
	}
	r.adapters[name] = a
	return nil
}

// Initialize initializes every registered adapter before the worker starts
// consuming jobs. The first failure aborts startup so the worker fails closed.
func (r *Registry) Initialize(ctx context.Context, logger *zap.Logger) error {
	for _, name := range r.Names() {
		a, _ := r.Lookup(name)
		if err := a.Initialize(ctx, logger); err != nil {
			return fmt.Errorf("adapters: initialize %q: %w", name, err)
		}
	}
	return nil
}

// Lookup returns the adapter with the given name.
func (r *Registry) Lookup(name string) (ScannerAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	return a, ok
}

// LookupExecutable returns the adapter with the given name if it implements
// Executable; otherwise ok is false.
func (r *Registry) LookupExecutable(name string) (ScannerAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	if !ok {
		return nil, false
	}
	return a, true
}

// Names lists registered adapter names in sorted order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.adapters))
	for n := range r.adapters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
