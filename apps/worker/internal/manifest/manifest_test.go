package manifest_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
)

func validBuilder() *manifest.Builder {
	b := manifest.NewBuilder(
		uuid.New().String(),
		uuid.New().String(),
		uuid.New().String(),
		"https://example.com",
		"standard_web_mvp",
	)
	b.SetProfileVersion("1.2.0")
	b.SetStartedAt(time.Now().UTC())
	b.AddScanner(manifest.ScannerComponent{
		ScannerID:      "nuclei",
		ScannerVersion: "3.3.0",
		AdapterVersion: "1.0.0",
		ImageDigest:    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		RulesetCatalog: "kelvin.safe.web.v1",
		RulesetDigest:  "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	})
	b.AddScanner(manifest.ScannerComponent{
		ScannerID:      "zap_baseline",
		ScannerVersion: "2.14.0",
		AdapterVersion: "1.0.0",
		ImageDigest:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	})
	b.SetResourceLimits(manifest.ResourceLimits{
		HardDeadlineSeconds: 900,
		MemoryLimit:         "512m",
		CPUQuota:            "2.0",
		RequestsPerSecond:   25,
	})
	b.SetEffectiveConfig(map[string]any{
		"spider_max_depth": 3,
		"auth_token":       "sensitive-jwt-token-xyz",
		"headers": map[string]any{
			"Authorization": "Bearer super-secret-key",
			"User-Agent":    "Kelvin-Security-Scanner/1.0",
		},
	})
	return b
}

func TestManifestBuildAndVerify(t *testing.T) {
	b := validBuilder()
	m, err := b.Build()
	if err != nil {
		t.Fatalf("unexpected build error: %v", err)
	}

	if m.Digest == "" {
		t.Fatalf("expected non-empty cryptographic digest")
	}

	valid, err := manifest.VerifyDigest(m)
	if err != nil {
		t.Fatalf("verify digest error: %v", err)
	}
	if !valid {
		t.Fatalf("expected digest to be valid for unmodified manifest")
	}
}

func TestManifestImmutabilityTamperDetection(t *testing.T) {
	b := validBuilder()
	m, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with scanner version
	m.Scanners[0].ScannerVersion = "9.9.9"
	valid, err := manifest.VerifyDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatalf("expected verification to fail after tampering with scanner version")
	}

	// Restore and tamper with target
	m.Scanners[0].ScannerVersion = "3.3.0"
	m.Target = "https://malicious-target.com"
	valid, _ = manifest.VerifyDigest(m)
	if valid {
		t.Fatalf("expected verification to fail after tampering with target")
	}
}

func TestManifestSecretRedaction(t *testing.T) {
	b := validBuilder()
	m, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	if m.EffectiveConfig["auth_token"] != manifest.RedactedValue {
		t.Fatalf("expected auth_token to be redacted, got: %v", m.EffectiveConfig["auth_token"])
	}

	headers, ok := m.EffectiveConfig["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected headers map")
	}
	if headers["Authorization"] != manifest.RedactedValue {
		t.Fatalf("expected Authorization header to be redacted, got: %v", headers["Authorization"])
	}
	if headers["User-Agent"] != "Kelvin-Security-Scanner/1.0" {
		t.Fatalf("expected non-sensitive User-Agent to be preserved")
	}
}

func TestDeterministicDigestOrdering(t *testing.T) {
	tenantID := uuid.New().String()
	assessmentID := uuid.New().String()
	runID := uuid.New().String()
	fixedTime := time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC)

	b1 := manifest.NewBuilder(tenantID, assessmentID, runID, "https://example.com", "standard")
	b1.SetStartedAt(fixedTime)
	b1.AddScanner(manifest.ScannerComponent{ScannerID: "nuclei", ScannerVersion: "3.3.0", AdapterVersion: "1.0.0"})
	b1.AddScanner(manifest.ScannerComponent{ScannerID: "zap", ScannerVersion: "2.14.0", AdapterVersion: "1.0.0"})
	m1, err := b1.Build()
	if err != nil {
		t.Fatal(err)
	}

	b2 := manifest.NewBuilder(tenantID, assessmentID, runID, "https://example.com", "standard")
	b2.SetStartedAt(fixedTime)
	b2.AddScanner(manifest.ScannerComponent{ScannerID: "zap", ScannerVersion: "2.14.0", AdapterVersion: "1.0.0"})
	b2.AddScanner(manifest.ScannerComponent{ScannerID: "nuclei", ScannerVersion: "3.3.0", AdapterVersion: "1.0.0"})
	m2, err := b2.Build()
	if err != nil {
		t.Fatal(err)
	}

	if m1.Digest != m2.Digest {
		t.Fatalf("expected deterministic digest matching regardless of scanner order: %s vs %s", m1.Digest, m2.Digest)
	}
}

func TestMemoryStoreImmutability(t *testing.T) {
	store := manifest.NewMemoryStore()
	ctx := context.Background()

	b := validBuilder()
	m, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Save(ctx, m); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	// Attempt to save again with same coordinates (overwriting)
	err = store.Save(ctx, m)
	if err != manifest.ErrManifestExists {
		t.Fatalf("expected ErrManifestExists, got: %v", err)
	}

	// Retrieve stored manifest
	retrieved, err := store.Get(ctx, m.TenantID, m.AssessmentID, m.RunID)
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if retrieved.Digest != m.Digest {
		t.Fatalf("retrieved manifest digest mismatch")
	}
}

func TestManifestValidationRejectsMalformed(t *testing.T) {
	b := validBuilder()
	b = manifest.NewBuilder("", "a-1", "r-1", "https://example.com", "p-1")
	if _, err := b.Build(); err == nil {
		t.Fatalf("expected error on empty tenant_id")
	}

	b = manifest.NewBuilder("t-1", "a-1", "r-1", "not-a-valid-url", "p-1")
	b.AddScanner(manifest.ScannerComponent{ScannerID: "s1", ScannerVersion: "1.0", AdapterVersion: "1.0"})
	if _, err := b.Build(); err == nil {
		t.Fatalf("expected error on invalid URL target")
	}

	b = manifest.NewBuilder("t-1", "a-1", "r-1", "https://example.com", "p-1")
	// zero scanners
	if _, err := b.Build(); err == nil {
		t.Fatalf("expected error on zero scanners")
	}
}
