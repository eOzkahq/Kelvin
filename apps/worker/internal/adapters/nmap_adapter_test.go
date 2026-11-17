package adapters

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

func TestVerifiedNmapAdapter_RuntimeVerification(t *testing.T) {
	incompleteVerifier := func(_ context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: "7.95",
			AdapterVersion: "1.0.0",
		}, nil
	}

	adapter := NewVerifiedNmapAdapter(incompleteVerifier, func(_ context.Context, _ Task) ([]byte, error) {
		return nil, nil
	})

	err := adapter.Initialize(context.Background(), zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "pinned identity") {
		t.Fatalf("expected incomplete identity error, got: %v", err)
	}

	completeVerifier := func(_ context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: PinnedNmapScannerVersion,
			AdapterVersion: PinnedNmapAdapterVersion,
			ImageReference: PinnedNmapImageReference,
			ImageDigest:    PinnedNmapImageDigest,
		}, nil
	}

	validAdapter := NewVerifiedNmapAdapter(completeVerifier, func(_ context.Context, _ Task) ([]byte, error) {
		return []byte(sampleNmapXML), nil
	})

	if err := validAdapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatalf("expected successful initialization, got: %v", err)
	}
}

func TestVerifiedNmapAdapter_Execution(t *testing.T) {
	verifier := func(_ context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: PinnedNmapScannerVersion,
			AdapterVersion: PinnedNmapAdapterVersion,
			ImageReference: PinnedNmapImageReference,
			ImageDigest:    PinnedNmapImageDigest,
		}, nil
	}

	runner := func(_ context.Context, _ Task) ([]byte, error) {
		return []byte(sampleNmapXML), nil
	}

	adapter := NewVerifiedNmapAdapter(verifier, runner)
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatalf("failed to initialize adapter: %v", err)
	}

	task := Task{
		JobID:        uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Scanner:      ScannerNmap,
		Target:       "https://mail.example.com",
		ProfileID:    "standard",
		HardDeadline: 2 * time.Minute,
	}

	res, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("expected successful execution, got: %v", err)
	}

	if res.Status != StatusCompleted {
		t.Errorf("expected COMPLETED, got %s", res.Status)
	}
	if len(res.Findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(res.Findings))
	}
}

func TestOCINmapRunnerWithScope_RejectsOutOfScope(t *testing.T) {
	resolver := &candidateMockResolver{
		mapping: map[string][]netip.Addr{
			"in-scope.com": {netip.MustParseAddr("93.184.216.34")},
		},
	}
	provider := func(_ context.Context, _ Task) (scope.Policy, error) {
		return scope.NewPolicy([]string{"in-scope.com"}, nil, resolver)
	}

	mockExec := sandbox.NewFake()
	runner := NewOCINmapRunnerWithScope(mockExec, provider)

	// Target out of scope
	outTask := Task{
		JobID:        uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Scanner:      ScannerNmap,
		Target:       "https://out-of-scope.org",
		ProfileID:    "standard",
		HardDeadline: time.Minute,
	}

	_, err := runner(context.Background(), outTask)
	if err == nil || !strings.Contains(err.Error(), "rejected by scope policy") {
		t.Fatalf("expected scope rejection error, got: %v", err)
	}
}

func TestNmapRegistryIntegration(t *testing.T) {
	reg := NewRegistry()
	mockExec := sandbox.NewFake()

	if err := RegisterDefaultAdapters(reg, mockExec); err != nil {
		t.Fatalf("failed to register default adapters: %v", err)
	}

	if err := reg.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatalf("failed to initialize registry: %v", err)
	}

	meta, ok := reg.Metadata(ScannerNmap)
	if !ok {
		t.Fatalf("ScannerNmap was not registered in default registry")
	}

	if meta.ID != ScannerNmap {
		t.Errorf("expected metadata ID %s, got %s", ScannerNmap, meta.ID)
	}
	if meta.VersionPolicy.ImageReference != PinnedNmapImageReference {
		t.Errorf("expected image ref %s, got %s", PinnedNmapImageReference, meta.VersionPolicy.ImageReference)
	}

	adapter, err := reg.GetAdapter(ScannerNmap)
	if err != nil {
		t.Fatalf("failed to create Nmap adapter from registry: %v", err)
	}
	if adapter.Name() != ScannerNmap {
		t.Errorf("expected adapter name %s, got %s", ScannerNmap, adapter.Name())
	}
}
