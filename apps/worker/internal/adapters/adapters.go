// Package adapters defines the scanner adapter contract and registry
// (Nmap, Nuclei, OpenVAS, Trivy, ... — concrete adapters land with the
// Phase 2 engine milestones; ADR-0005 governs their sandboxing).
//
// See docs/architecture/EXECUTION_ISOLATION.md §5 for the normative adapter
// contract: task ingestion, sandbox execution, and structured finding egress.
package adapters

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Adapter is one registered scanner engine (name-only, for backward
// compatibility with adapters that have not yet adopted Execute).
type Adapter interface {
	Name() string
}

// Executable is implemented by scanner adapters that run inside the worker
// sandbox and return structured findings. Execute receives a validated Task
// and a context carrying the hard execution deadline; cancellation kills the
// container.
type Executable interface {
	Adapter
	Execute(context.Context, Task) (Result, error)
}

// Registry maps adapter names to implementations, built once at startup.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds an adapter; duplicate names are rejected.
func (r *Registry) Register(a Adapter) error {
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

// Lookup returns the adapter with the given name.
func (r *Registry) Lookup(name string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	return a, ok
}

// LookupExecutable returns the adapter with the given name if it implements
// Executable; otherwise ok is false.
func (r *Registry) LookupExecutable(name string) (Executable, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	if !ok {
		return nil, false
	}
	exec, ok := a.(Executable)
	return exec, ok
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
