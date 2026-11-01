package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

type registryTestAdapter struct {
	name      string
	version   string
	caps      Capabilities
	initErr   error
	healthErr error
	initCount atomic.Int32
}

func (a *registryTestAdapter) Name() string    { return a.name }
func (a *registryTestAdapter) Version() string { return a.version }
func (a *registryTestAdapter) VerifyRuntimeVersion(ctx context.Context) (RuntimeVersionInfo, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeVersionInfo{}, err
	}
	return RuntimeVersionInfo{ScannerVersion: a.version, AdapterVersion: a.version}, nil
}
func (a *registryTestAdapter) Initialize(context.Context, *zap.Logger) error {
	a.initCount.Add(1)
	return a.initErr
}
func (a *registryTestAdapter) ValidateConfig(json.RawMessage) error          { return nil }
func (a *registryTestAdapter) Capabilities() Capabilities                    { return cloneCapabilities(a.caps) }
func (a *registryTestAdapter) Execute(context.Context, Task) (Result, error) { return Result{}, nil }
func (a *registryTestAdapter) Cancel() error                                 { return nil }
func (a *registryTestAdapter) Health(context.Context) error                  { return a.healthErr }
func (a *registryTestAdapter) Result() (Result, error)                       { return Result{}, ErrNoResult }

func registryTestCaps() Capabilities {
	return Capabilities{
		CheckCategories:      []string{"passive", "tls"},
		Flags:                []string{"certificate-validation"},
		SupportedTargetTypes: []string{"url", "hostname"},
		SupportedProtocols:   []string{"http", "https"},
		PassiveOnly:          true, RequiresNetwork: true, SupportsCancel: true,
		MaxConcurrency: 2, MaxRequestRate: 2, MaxRequests: 100,
	}
}

func registryTestMetadata(id string, caps Capabilities) Metadata {
	return Metadata{
		ID: id, DisplayName: "Test Scanner", Version: "1.2.3",
		SupportedTargets: append([]string(nil), caps.SupportedTargetTypes...),
		Capabilities:     cloneCapabilities(caps), ConfigVersion: "1.0",
		VersionPolicy: VersionPolicy{ScannerVersion: "1.2.3"},
	}
}

func TestRegistryFactoryInitializationDiscoveryAndDefensiveMetadata(t *testing.T) {
	registry := NewRegistry()
	caps := registryTestCaps()
	var factoryCalls atomic.Int32
	adapter := &registryTestAdapter{name: "tls_test", version: "1.2.3", caps: caps}
	err := registry.RegisterAdapter(registryTestMetadata("tls_test", caps), func() ScannerAdapter {
		factoryCalls.Add(1)
		return adapter
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetAdapter("tls_test"); !errors.Is(err, ErrAdapterUnavailable) {
		t.Fatalf("GetAdapter before initialization error = %v, want unavailable", err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	got, err := registry.GetAdapter("tls_test")
	if err != nil {
		t.Fatal(err)
	}
	if got != adapter || factoryCalls.Load() != 1 || adapter.initCount.Load() != 1 {
		t.Fatalf("factory/init counts or cached instance incorrect: calls=%d init=%d", factoryCalls.Load(), adapter.initCount.Load())
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if adapter.initCount.Load() != 1 {
		t.Fatalf("Initialize called more than once: %d", adapter.initCount.Load())
	}
	if available := registry.ListAvailable(); len(available) != 1 || available[0].ID != "tls_test" {
		t.Fatalf("ListAvailable() = %+v", available)
	}
	for _, capability := range []string{"tls", "certificate-validation", "https", "hostname", "passive_only", "network", "cancellation"} {
		if matches := registry.FindByCapability(capability); len(matches) != 1 || matches[0].ID != "tls_test" {
			t.Errorf("FindByCapability(%q) = %+v", capability, matches)
		}
	}
	listed := registry.ListAvailable()
	listed[0].SupportedTargets[0] = "mutated"
	listed[0].Capabilities.CheckCategories[0] = "mutated"
	metadata, ok := registry.Metadata("tls_test")
	if !ok || metadata.SupportedTargets[0] != "url" || metadata.Capabilities.CheckCategories[0] != "passive" {
		t.Fatalf("metadata copy was mutable: %+v", metadata)
	}
}

func TestRegistryRejectsDuplicateAndUnknownScanner(t *testing.T) {
	registry := NewRegistry()
	caps := registryTestCaps()
	adapter := &registryTestAdapter{name: "tls_test", version: "1.2.3", caps: caps}
	factory := func() ScannerAdapter { return adapter }
	if err := registry.RegisterAdapter(registryTestMetadata("tls_test", caps), factory); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterAdapter(registryTestMetadata("tls_test", caps), factory); !errors.Is(err, ErrDuplicateAdapter) {
		t.Fatalf("duplicate registration error = %v", err)
	}
	if _, err := registry.GetAdapter("missing"); !errors.Is(err, ErrAdapterNotFound) {
		t.Fatalf("unknown scanner error = %v", err)
	}
	if len(registry.ListAvailable()) != 0 {
		t.Fatal("uninitialized scanner appeared in ListAvailable")
	}
}

func TestVersionPolicyRequiresImmutableExternalImageAndNucleiCatalog(t *testing.T) {
	caps := registryTestCaps()
	caps.RequiresSandbox = true
	if err := validateVersionPolicy("zap", "1.2.3", caps, VersionPolicy{ScannerVersion: "2.14.0"}); err == nil {
		t.Fatal("expected missing image pin rejection")
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := VersionPolicy{ScannerVersion: "2.14.0", ImageDigest: digest, ImageReference: "registry.example/zap@" + digest}
	if err := validateVersionPolicy("zap", "1.2.3", caps, policy); err != nil {
		t.Fatal(err)
	}
	if err := compareRuntimeVersion("zap", "1.2.3", policy, RuntimeVersionInfo{ScannerVersion: "2.14.1", AdapterVersion: "1.2.3", ImageReference: policy.ImageReference, ImageDigest: digest}); err == nil {
		t.Fatal("expected unexpected scanner version rejection")
	}
	nuclei := VersionPolicy{ScannerVersion: "3.3.0", TemplateCatalogVersion: "kelvin.safe.web.v1", TemplateCatalogDigest: digest}
	if err := validateVersionPolicy(ScannerNuclei, "1.2.3", registryTestCaps(), nuclei); err != nil {
		t.Fatal(err)
	}
	nuclei.TemplateCatalogDigest = ""
	if err := validateVersionPolicy(ScannerNuclei, "1.2.3", registryTestCaps(), nuclei); err == nil {
		t.Fatal("expected unpinned nuclei catalog rejection")
	}
}

func TestRegistryRechecksRuntimeAndStampsOutput(t *testing.T) {
	registry := NewRegistry()
	caps := registryTestCaps()
	adapter := &registryTestAdapter{name: "tls_test", version: "1.2.3", caps: caps}
	if err := registry.RegisterAdapter(registryTestMetadata("tls_test", caps), func() ScannerAdapter { return adapter }); err != nil {
		t.Fatal(err)
	}
	if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := registry.VerifyRuntime(context.Background(), "tls_test"); err != nil {
		t.Fatal(err)
	}
	out := &ScannerOutputEnvelope{}
	if err := registry.StampOutput("tls_test", out); err != nil {
		t.Fatal(err)
	}
	if out.Metadata.ScannerID != "tls_test" || out.Metadata.ScannerVersion != "1.2.3" || out.Metadata.AdapterVersion != "1.2.3" {
		t.Fatalf("runtime identity not stamped: %+v", out.Metadata)
	}
	adapter.version = "9.9.9"
	if err := registry.VerifyRuntime(context.Background(), "tls_test"); !errors.Is(err, ErrAdapterUnavailable) {
		t.Fatalf("version drift error = %v", err)
	}
}

func TestRegistryMarksFactoryAndHealthFailuresUnavailable(t *testing.T) {
	caps := registryTestCaps()
	t.Run("metadata mismatch", func(t *testing.T) {
		registry := NewRegistry()
		if err := registry.RegisterAdapter(registryTestMetadata("tls_test", caps), func() ScannerAdapter {
			return &registryTestAdapter{name: "other", version: "1.2.3", caps: caps}
		}); err != nil {
			t.Fatal(err)
		}
		if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
			t.Fatal(err)
		}
		metadata, _ := registry.Metadata("tls_test")
		if metadata.Availability != AvailabilityUnavailable || metadata.UnavailableReason == "" {
			t.Fatalf("metadata mismatch not marked unavailable: %+v", metadata)
		}
		if _, err := registry.GetAdapter("tls_test"); !errors.Is(err, ErrAdapterUnavailable) {
			t.Fatalf("GetAdapter error = %v", err)
		}
	})
	t.Run("health failure", func(t *testing.T) {
		registry := NewRegistry()
		adapter := &registryTestAdapter{name: "tls_test", version: "1.2.3", caps: caps, healthErr: errors.New("runtime offline")}
		if err := registry.RegisterAdapter(registryTestMetadata("tls_test", caps), func() ScannerAdapter { return adapter }); err != nil {
			t.Fatal(err)
		}
		if err := registry.Initialize(context.Background(), zap.NewNop()); err != nil {
			t.Fatal(err)
		}
		metadata, _ := registry.Metadata("tls_test")
		if metadata.Availability != AvailabilityUnavailable || len(registry.ListAvailable()) != 0 {
			t.Fatalf("health failure not reflected: %+v", metadata)
		}
	})
}
