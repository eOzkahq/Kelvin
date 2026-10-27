// Package adapters defines the scanner adapter contract and registry
// (Nmap, Nuclei, OpenVAS, Trivy, ... — concrete adapters land with the
// Phase 2 engine milestones; ADR-0005 governs their sandboxing).
package adapters

import (
	"fmt"
	"sort"
	"sync"
)

// Adapter is one scanner engine executable under the worker sandbox.
type Adapter interface {
	Name() string
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
