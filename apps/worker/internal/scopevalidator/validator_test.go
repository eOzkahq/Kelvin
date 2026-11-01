package scopevalidator_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/scopevalidator"
	"go.uber.org/zap"
)

func sampleFinding(title, asset, targetURL string) json.RawMessage {
	m := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       "MEDIUM",
		"confidence":     0.8,
		"target": map[string]any{
			"asset": asset,
			"url":   targetURL,
		},
		"vulnerability": map[string]any{
			"template_id": "cve-test",
		},
		"scanner": map[string]any{
			"name":            "nuclei",
			"adapter_version": "1.0.0",
		},
		"discovered_at": "2026-11-02T00:00:00Z",
	}
	raw, _ := json.Marshal(m)
	return raw
}

func TestFilterFindingsAcceptsInScope(t *testing.T) {
	v, err := scopevalidator.NewFromTarget("https://example.com/api", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	findings := []json.RawMessage{
		sampleFinding("In-Scope Finding 1", "example.com", "https://example.com/login"),
		sampleFinding("In-Scope Finding 2", "example.com", "https://example.com/users"),
	}

	accepted, violations, err := v.FilterFindings(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected filter error: %v", err)
	}

	if len(accepted) != 2 {
		t.Fatalf("expected 2 accepted findings, got %d", len(accepted))
	}
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(violations))
	}
}

func TestFilterFindingsRejectsOutOfScope(t *testing.T) {
	v, err := scopevalidator.NewFromTarget("https://example.com", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	findings := []json.RawMessage{
		sampleFinding("Valid Finding", "example.com", "https://example.com/index.html"),
		sampleFinding("Rogue Target Finding", "malicious-site.com", "https://malicious-site.com/exploit"),
		sampleFinding("External CDN Finding", "cdn.unauthorized-thirdparty.net", "https://cdn.unauthorized-thirdparty.net/script.js"),
	}

	accepted, violations, err := v.FilterFindings(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}

	if len(accepted) != 1 {
		t.Fatalf("expected 1 accepted finding, got %d", len(accepted))
	}
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}

	diags := scopevalidator.ToDiagnostics(violations)
	if len(diags) != 2 {
		t.Fatalf("expected 2 diagnostics, got %d", len(diags))
	}
	for _, d := range diags {
		if d.Code != "OUT_OF_SCOPE_TARGET_REJECTED" || d.Level != "info" {
			t.Fatalf("unexpected diagnostic structure: %+v", d)
		}
	}
}

func TestFilterFindingsRejectsProhibitedInternalIPs(t *testing.T) {
	v, err := scopevalidator.NewFromTarget("https://example.com", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	findings := []json.RawMessage{
		sampleFinding("Localhost Probe Finding", "127.0.0.1", "http://127.0.0.1:8080/admin"),
		sampleFinding("AWS Metadata Finding", "169.254.169.254", "http://169.254.169.254/latest/meta-data"),
		sampleFinding("Private RFC1918 Finding", "10.0.0.5", "http://10.0.0.5/internal"),
	}

	accepted, violations, err := v.FilterFindings(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}

	if len(accepted) != 0 {
		t.Fatalf("expected 0 accepted findings for prohibited targets, got %d", len(accepted))
	}
	if len(violations) != 3 {
		t.Fatalf("expected 3 violations, got %d", len(violations))
	}
}

func TestFilterFindingsRejectsMissingTarget(t *testing.T) {
	v, err := scopevalidator.NewFromTarget("https://example.com", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	m := map[string]any{
		"schema_version": "1.0",
		"title":          "Targetless Finding",
		"severity":       "LOW",
		"confidence":     0.5,
		"target":         map[string]any{},
		"vulnerability":  map[string]any{"template_id": "test"},
		"scanner":        map[string]any{"name": "test", "adapter_version": "1.0.0"},
		"discovered_at":  "2026-11-02T00:00:00Z",
	}
	raw, _ := json.Marshal(m)

	accepted, violations, err := v.FilterFindings(context.Background(), []json.RawMessage{raw})
	if err != nil {
		t.Fatal(err)
	}

	if len(accepted) != 0 {
		t.Fatalf("expected finding with empty target to be rejected")
	}
	if len(violations) != 1 || !strings.Contains(violations[0].Reason, "missing target reference") {
		t.Fatalf("unexpected violation: %+v", violations)
	}
}
