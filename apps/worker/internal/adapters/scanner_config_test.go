package adapters

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDefaultScannerConfigs(t *testing.T) {
	ids := []string{ScannerHTTPPreflight, ScannerTLSAssessor, ScannerHTTPHeaders, ScannerZAPBaseline, ScannerNuclei}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			cfg, err := DefaultScannerConfig(id)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("default config invalid: %v", err)
			}
			if cfg.SchemaVersion != "1.0" || cfg.ExecutionMode != "PASSIVE" || cfg.RequestTimeoutSeconds != 10 {
				t.Fatalf("unexpected default config: %+v", cfg)
			}
		})
	}
	if _, err := DefaultScannerConfig("nmap"); err == nil {
		t.Fatal("unsupported scanner received a default config")
	}
}

func TestDecodeScannerConfigAppliesDefaultsAndRejectsUnsafeOptions(t *testing.T) {
	cfg, err := DecodeScannerConfig([]byte(`{"schema_version":"1.0","scanner_id":"zap"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ZAP == nil || cfg.ZAP.MaxURLs != 100 || cfg.ZAP.MaxDepth != 3 || cfg.RequestsPerSecond != 1 {
		t.Fatalf("expected documented ZAP defaults, got %+v", cfg)
	}
	cases := []struct {
		name string
		json string
	}{
		{"unknown field", `{"schema_version":"1.0","scanner_id":"zap","args":["--active"]}`},
		{"active mode", `{"schema_version":"1.0","scanner_id":"zap","execution_mode":"ACTIVE"}`},
		{"excessive request rate", `{"schema_version":"1.0","scanner_id":"zap","requests_per_second":6}`},
		{"excessive duration", `{"schema_version":"1.0","scanner_id":"zap","max_duration_seconds":3601}`},
		{"excessive crawl depth", `{"schema_version":"1.0","scanner_id":"zap","zap":{"max_depth":6}}`},
		{"arbitrary template set", `{"schema_version":"1.0","scanner_id":"nuclei","nuclei":{"template_set_id":"/tmp/custom.yaml","severity_allowlist":["low"]}}`},
		{"incomplete nuclei settings", `{"schema_version":"1.0","scanner_id":"nuclei","nuclei":{"template_set_id":"kelvin.safe.web.v1"}}`},
		{"unsupported scanner", `{"schema_version":"1.0","scanner_id":"nmap"}`},
		{"wrong schema version", `{"schema_version":"2.0","scanner_id":"nuclei"}`},
		{"cross-scanner settings", `{"schema_version":"1.0","scanner_id":"tls_assessor","nuclei":{"template_set_id":"kelvin.safe.web.v1","severity_allowlist":["low"]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeScannerConfig([]byte(tc.json)); err == nil {
				t.Fatal("DecodeScannerConfig accepted unsafe or unsupported config")
			}
		})
	}
}

func TestScannerConfigCannotWidenProfile(t *testing.T) {
	cfg, err := DefaultScannerConfig(ScannerNuclei)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateWithinProfile(ProfileBudget{RequestsPerSecond: 2, MaxConcurrency: 2, MaxRequestsPerTarget: 5000, MaxDuration: 4 * time.Minute}); err == nil {
		t.Fatal("config exceeded profile deadline without rejection")
	}
	cfg.MaxDurationSeconds = 120
	if err := cfg.ValidateWithinProfile(ProfileBudget{RequestsPerSecond: 2, MaxConcurrency: 2, MaxRequestsPerTarget: 5000, MaxDuration: 4 * time.Minute}); err != nil {
		t.Fatalf("bounded config rejected: %v", err)
	}
	if err := cfg.ValidateWithinProfile(ProfileBudget{RequestsPerSecond: 1, MaxConcurrency: 2, MaxRequestsPerTarget: 5000, MaxDuration: 4 * time.Minute}); err == nil {
		t.Fatal("config exceeded profile rate without rejection")
	}
}

func TestScannerConfigRoundTripPreservesVersionAndSettings(t *testing.T) {
	cfg, err := DefaultScannerConfig(ScannerNuclei)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeScannerConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ScannerID != ScannerNuclei || decoded.Nuclei.TemplateSetID != "kelvin.safe.web.v1" || decoded.SchemaVersion != ScannerConfigVersion {
		t.Fatalf("unexpected decoded config: %+v", decoded)
	}
}

func TestReferenceAdapterValidatesMVPConfigBeforeExecution(t *testing.T) {
	adapter := &ReferenceAdapter{AdapterName: ScannerZAPBaseline}
	defaults, err := DefaultScannerConfig(ScannerZAPBaseline)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(defaults)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateConfig(raw); err != nil {
		t.Fatalf("valid default config rejected: %v", err)
	}
	if err := adapter.ValidateConfig([]byte(`{"schema_version":"1.0","scanner_id":"zap","execution_mode":"ACTIVE"}`)); err == nil {
		t.Fatal("adapter accepted active mode")
	}
}
