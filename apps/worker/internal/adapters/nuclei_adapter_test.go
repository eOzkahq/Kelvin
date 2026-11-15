package adapters

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestNucleiAdapter_InitializationAndVerification(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	validVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion:         "3.11.1",
			AdapterVersion:         "1.0.0",
			ImageReference:         "kelvin/scanner-nuclei:3.11.1",
			ImageDigest:            "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696",
			TemplateCatalogVersion: "kelvin.safe.web.v1",
			TemplateCatalogDigest:  "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return []byte(`{"template-id":"git-config","info":{"name":"Git Config Disclosure","severity":"low"},"type":"http","host":"example.internal","matched-at":"https://example.internal/.git/config"}` + "\n"), nil
	}

	adapter := NewVerifiedNucleiAdapter(validVerifier, dummyRunner)
	if err := adapter.Initialize(ctx, logger); err != nil {
		t.Fatalf("adapter.Initialize failed: %v", err)
	}

	// Verify adapter capabilities
	caps := adapter.Capabilities()
	if !caps.ActiveScanning {
		t.Errorf("Nuclei adapter must support active scanning")
	}
	if !caps.RequiresSandbox {
		t.Errorf("Nuclei adapter must require sandbox execution")
	}
	if caps.MaxConcurrency > 2 {
		t.Errorf("Nuclei adapter max concurrency cannot exceed 2")
	}
}

func TestNucleiAdapter_RejectsInvalidTemplateCatalog(t *testing.T) {
	ctx := context.Background()

	invalidCatalogVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion:         "3.11.1",
			AdapterVersion:         "1.0.0",
			ImageReference:         "kelvin/scanner-nuclei:3.11.1",
			ImageDigest:            "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696",
			TemplateCatalogVersion: "untrusted.catalog.v9",
			TemplateCatalogDigest:  "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return nil, nil
	}

	adapter := NewVerifiedNucleiAdapter(invalidCatalogVerifier, dummyRunner)
	_, err := adapter.VerifyRuntimeVersion(ctx)
	if err == nil {
		t.Fatalf("expected error for untrusted template catalog, got nil")
	}
}
