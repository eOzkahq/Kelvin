package adapters

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestZAPBaselineAdapter_InitializationAndVerification(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	validVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: "2.16.0",
			AdapterVersion: "1.0.0",
			ImageReference: "kelvin/scanner-zap:2.16.0",
			ImageDigest:    "sha256:4b94f923b320d7be7d25e0a6d05fca1c676b772c679b380bf9cfd5ac5bbf6c41",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return []byte(`{"@version":"2.16.0","site":[{"@name":"http://target.internal","alerts":[]}]}`), nil
	}

	adapter := NewVerifiedZAPBaselineAdapter(validVerifier, dummyRunner)
	if err := adapter.Initialize(ctx, logger); err != nil {
		t.Fatalf("adapter.Initialize failed: %v", err)
	}

	// Verify adapter capabilities
	caps := adapter.Capabilities()
	if !caps.PassiveOnly {
		t.Errorf("ZAP baseline adapter must be passive only")
	}
	if caps.ActiveScanning {
		t.Errorf("ZAP baseline adapter must not perform active scanning")
	}
	if !caps.RequiresSandbox {
		t.Errorf("ZAP baseline adapter must require sandbox execution")
	}
	if caps.MaxConcurrency > 2 {
		t.Errorf("ZAP baseline adapter max concurrency cannot exceed 2")
	}
}

func TestZAPBaselineAdapter_RejectsMissingRuntimeInfo(t *testing.T) {
	ctx := context.Background()

	invalidVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion: "", // Missing version
			ImageDigest:    "",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return nil, nil
	}

	adapter := NewVerifiedZAPBaselineAdapter(invalidVerifier, dummyRunner)
	_, err := adapter.VerifyRuntimeVersion(ctx)
	if err == nil {
		t.Fatalf("expected error for incomplete runtime version info, got nil")
	}
}
