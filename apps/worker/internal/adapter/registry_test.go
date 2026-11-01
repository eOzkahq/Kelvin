package adapter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestScannerRegistryLifecycle(t *testing.T) {
	reg := NewScannerRegistry()
	ref := NewReferenceAdapter()
	_ = ref.Initialize(context.Background(), zap.NewNop())

	meta := Registration{
		ID:                   "reference",
		DisplayName:          "Reference Scanner",
		Version:              "1.0.0",
		SupportedTargetTypes: []string{"hostname", "ipv4", "url"},
	}

	// Successful registration
	if err := reg.Register(ref, meta); err != nil {
		t.Fatalf("failed to register adapter: %v", err)
	}

	// Duplicate registration must fail
	if err := reg.Register(ref, meta); !errors.Is(err, ErrAdapterAlreadyRegistered) {
		t.Fatalf("expected ErrAdapterAlreadyRegistered on duplicate, got %v", err)
	}

	// Lookup registered adapter
	a, retrievedMeta, err := reg.Lookup("reference")
	if err != nil {
		t.Fatalf("failed to lookup registered adapter: %v", err)
	}
	if a.Name() != "reference" {
		t.Fatalf("expected name 'reference', got %q", a.Name())
	}
	if retrievedMeta.DisplayName != "Reference Scanner" {
		t.Fatalf("expected DisplayName 'Reference Scanner', got %q", retrievedMeta.DisplayName)
	}

	// Capabilities discovery
	caps, err := reg.GetCapabilities("reference")
	if err != nil {
		t.Fatalf("failed to get capabilities: %v", err)
	}
	if !caps.PassiveOnly {
		t.Fatalf("expected passive_only=true")
	}

	// List available
	list := reg.ListAvailable()
	if len(list) != 1 {
		t.Fatalf("expected 1 registered adapter, got %d", len(list))
	}
	if list[0].ID != "reference" {
		t.Fatalf("expected first adapter 'reference', got %s", list[0].ID)
	}
}

func TestScannerRegistryUnknownAdapter(t *testing.T) {
	reg := NewScannerRegistry()

	_, _, err := reg.Lookup("nonexistent")
	if !errors.Is(err, ErrAdapterNotFound) {
		t.Fatalf("expected ErrAdapterNotFound, got %v", err)
	}

	_, err = reg.GetCapabilities("nonexistent")
	if !errors.Is(err, ErrAdapterNotFound) {
		t.Fatalf("expected ErrAdapterNotFound for capabilities, got %v", err)
	}
}

func TestScannerRegistryCheckAvailability(t *testing.T) {
	reg := NewScannerRegistry()
	ref := NewReferenceAdapter() // Uninitialized

	meta := Registration{
		ID:          "reference",
		DisplayName: "Reference Scanner",
	}
	_ = reg.Register(ref, meta)

	ctx := context.Background()
	// Should report UNAVAILABLE before init
	status, err := reg.CheckAvailability(ctx, "reference")
	if err != nil {
		t.Fatalf("check availability failed: %v", err)
	}
	if status.State != HealthStateUnavailable {
		t.Fatalf("expected UNAVAILABLE, got %s", status.State)
	}

	// Initialize adapter and re-check
	_ = ref.Initialize(ctx, zap.NewNop())
	status, err = reg.CheckAvailability(ctx, "reference")
	if err != nil {
		t.Fatalf("check availability failed: %v", err)
	}
	if status.State != HealthStateHealthy {
		t.Fatalf("expected HEALTHY, got %s", status.State)
	}
}

func TestScannerRegistryConcurrentAccess(t *testing.T) {
	reg := NewScannerRegistry()
	ref := NewReferenceAdapter()
	_ = ref.Initialize(context.Background(), zap.NewNop())
	_ = reg.Register(ref, Registration{ID: "reference"})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _, err := reg.Lookup("reference")
				if err != nil {
					t.Errorf("concurrent lookup failed: %v", err)
				}
				_ = reg.ListAvailable()
			}
		}()
	}
	wg.Wait()
}
