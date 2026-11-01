package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const ScannerConfigVersion = "1.0"
const ZAPSafetyProfileVersion = "kelvin.zap.baseline.v1"

const (
	ScannerHTTPPreflight = "http_preflight"
	ScannerTLSAssessor   = "tls_assessor"
	ScannerHTTPHeaders   = "http_security_headers"
	ScannerZAPBaseline   = "zap"
	ScannerNuclei        = "nuclei"
)

// ScannerConfigV1 is the typed, versioned allow-list for MVP scanner settings.
// Only the settings block appropriate for ScannerID may be present.
type ScannerConfigV1 struct {
	SchemaVersion         string          `json:"schema_version"`
	ScannerID             string          `json:"scanner_id"`
	ExecutionMode         string          `json:"execution_mode"`
	RequestTimeoutSeconds int             `json:"request_timeout_seconds"`
	MaxDurationSeconds    int             `json:"max_duration_seconds"`
	RequestsPerSecond     int             `json:"requests_per_second"`
	MaxConcurrency        int             `json:"max_concurrency"`
	ZAP                   *ZAPSettings    `json:"zap,omitempty"`
	Nuclei                *NucleiSettings `json:"nuclei,omitempty"`
}

type ZAPSettings struct {
	SafetyProfile string `json:"safety_profile"`
	MaxChildren   int    `json:"max_children"`
	MaxDepth      int    `json:"max_depth"`
}

type NucleiSettings struct {
	TemplateSetID     string   `json:"template_set_id"`
	SeverityAllowlist []string `json:"severity_allowlist"`
}

// ProfileBudget is the product-level ceiling applied after scanner config
// defaults. Scanner settings can narrow this budget but never raise it.
type ProfileBudget struct {
	RequestsPerSecond    int
	MaxConcurrency       int
	MaxRequestsPerTarget int
	MaxDuration          time.Duration
}

// DefaultScannerConfig returns the documented safe baseline for an MVP scanner.
func DefaultScannerConfig(scannerID string) (ScannerConfigV1, error) {
	cfg := ScannerConfigV1{
		SchemaVersion: ScannerConfigVersion, ScannerID: scannerID, ExecutionMode: "PASSIVE",
		RequestTimeoutSeconds: 10, MaxConcurrency: 1,
	}
	switch scannerID {
	case ScannerHTTPPreflight:
		cfg.MaxDurationSeconds, cfg.RequestsPerSecond = 30, 2
	case ScannerTLSAssessor, ScannerHTTPHeaders:
		cfg.MaxDurationSeconds, cfg.RequestsPerSecond = 60, 2
	case ScannerZAPBaseline:
		cfg.MaxDurationSeconds, cfg.RequestsPerSecond, cfg.MaxConcurrency = 600, 1, 1
		cfg.ZAP = &ZAPSettings{SafetyProfile: ZAPSafetyProfileVersion, MaxChildren: 10, MaxDepth: 2}
	case ScannerNuclei:
		cfg.MaxDurationSeconds, cfg.RequestsPerSecond, cfg.MaxConcurrency = 300, 2, 2
		cfg.Nuclei = &NucleiSettings{TemplateSetID: "kelvin.safe.web.v1", SeverityAllowlist: []string{"info", "low", "medium"}}
	default:
		return ScannerConfigV1{}, fmt.Errorf("adapters: unsupported MVP scanner %q", scannerID)
	}
	return cfg, nil
}

// DecodeScannerConfig applies defaults, rejects unknown fields, and validates
// the selected scanner's typed options. Empty input selects safe defaults.
func DecodeScannerConfig(raw []byte) (ScannerConfigV1, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
		ScannerID     string `json:"scanner_id"`
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ScannerConfigV1{}, fmt.Errorf("adapters: scanner_id is required to select configuration schema")
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.ScannerID == "" || header.SchemaVersion == "" {
		return ScannerConfigV1{}, fmt.Errorf("adapters: schema_version and scanner_id are required in scanner config")
	}
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawFields); err != nil {
		return ScannerConfigV1{}, fmt.Errorf("adapters: invalid scanner config: %w", err)
	}
	if nested, exists := rawFields["nuclei"]; exists {
		var nucleiFields map[string]json.RawMessage
		if err := json.Unmarshal(nested, &nucleiFields); err != nil || nucleiFields == nil {
			return ScannerConfigV1{}, fmt.Errorf("adapters: nuclei settings must be an object")
		}
		if _, ok := nucleiFields["template_set_id"]; !ok {
			return ScannerConfigV1{}, fmt.Errorf("adapters: nuclei template_set_id is required when nuclei settings are provided")
		}
		if _, ok := nucleiFields["severity_allowlist"]; !ok {
			return ScannerConfigV1{}, fmt.Errorf("adapters: nuclei severity_allowlist is required when nuclei settings are provided")
		}
	}
	cfg, err := DefaultScannerConfig(header.ScannerID)
	if err != nil {
		return ScannerConfigV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return ScannerConfigV1{}, fmt.Errorf("adapters: invalid scanner config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ScannerConfigV1{}, fmt.Errorf("adapters: scanner config contains trailing data")
	}
	if err := cfg.Validate(); err != nil {
		return ScannerConfigV1{}, err
	}
	return cfg, nil
}

func (cfg ScannerConfigV1) Validate() error {
	if cfg.SchemaVersion != ScannerConfigVersion {
		return fmt.Errorf("adapters: unsupported scanner config version %q", cfg.SchemaVersion)
	}
	if cfg.ExecutionMode != "PASSIVE" {
		return fmt.Errorf("adapters: only PASSIVE execution mode is enabled for MVP")
	}
	if cfg.RequestTimeoutSeconds < 1 || cfg.RequestTimeoutSeconds > 30 {
		return fmt.Errorf("adapters: request_timeout_seconds must be in 1..30")
	}
	if cfg.MaxDurationSeconds < 1 || cfg.MaxDurationSeconds > 3600 || cfg.MaxDurationSeconds < cfg.RequestTimeoutSeconds {
		return fmt.Errorf("adapters: max_duration_seconds must be >= request timeout and <= 3600")
	}
	if cfg.RequestsPerSecond < 1 || cfg.RequestsPerSecond > 5 {
		return fmt.Errorf("adapters: requests_per_second must be in 1..5")
	}
	if cfg.MaxConcurrency < 1 || cfg.MaxConcurrency > 2 {
		return fmt.Errorf("adapters: max_concurrency must be in 1..2")
	}
	switch cfg.ScannerID {
	case ScannerHTTPPreflight, ScannerTLSAssessor, ScannerHTTPHeaders:
		if cfg.ZAP != nil || cfg.Nuclei != nil {
			return fmt.Errorf("adapters: built-in scanner config cannot contain external scanner settings")
		}
	case ScannerZAPBaseline:
		if cfg.ZAP == nil || cfg.Nuclei != nil {
			return fmt.Errorf("adapters: zap configuration requires only zap settings")
		}
		if cfg.ZAP.SafetyProfile != ZAPSafetyProfileVersion {
			return fmt.Errorf("adapters: unsupported ZAP safety profile %q", cfg.ZAP.SafetyProfile)
		}
		if cfg.ZAP.MaxChildren < 1 || cfg.ZAP.MaxChildren > 10 || cfg.ZAP.MaxDepth < 1 || cfg.ZAP.MaxDepth > 2 {
			return fmt.Errorf("adapters: ZAP max_children must be in 1..10 and max_depth in 1..2")
		}
		if cfg.MaxDurationSeconds < 60 || cfg.MaxDurationSeconds > 600 || cfg.MaxDurationSeconds%60 != 0 {
			return fmt.Errorf("adapters: ZAP max_duration_seconds must be a whole minute in 60..600")
		}
		if cfg.RequestsPerSecond != 1 || cfg.MaxConcurrency != 1 {
			return fmt.Errorf("adapters: ZAP safety profile requires one request worker and request rate policy 1")
		}
	case ScannerNuclei:
		if cfg.Nuclei == nil || cfg.ZAP != nil {
			return fmt.Errorf("adapters: nuclei configuration requires only nuclei settings")
		}
		if cfg.Nuclei.TemplateSetID != "kelvin.safe.web.v1" {
			return fmt.Errorf("adapters: nuclei template_set_id is not approved")
		}
		if len(cfg.Nuclei.SeverityAllowlist) == 0 || len(cfg.Nuclei.SeverityAllowlist) > 5 {
			return fmt.Errorf("adapters: nuclei severity_allowlist must contain 1..5 entries")
		}
		seen := map[string]bool{}
		for _, severity := range cfg.Nuclei.SeverityAllowlist {
			if severity != "info" && severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
				return fmt.Errorf("adapters: nuclei severity %q is unsupported", severity)
			}
			if seen[severity] {
				return fmt.Errorf("adapters: duplicate nuclei severity %q", severity)
			}
			seen[severity] = true
		}
	default:
		return fmt.Errorf("adapters: unsupported MVP scanner %q", cfg.ScannerID)
	}
	return nil
}

// ValidateWithinProfile ensures scanner configuration cannot widen the
// product-level profile's request rate, concurrency, or deadline ceiling.
func (cfg ScannerConfigV1) ValidateWithinProfile(profile ProfileBudget) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if profile.RequestsPerSecond < 1 || profile.MaxConcurrency < 1 || profile.MaxRequestsPerTarget < 1 || profile.MaxDuration <= 0 {
		return fmt.Errorf("adapters: incomplete product profile budget")
	}
	if cfg.RequestsPerSecond > profile.RequestsPerSecond || cfg.MaxConcurrency > profile.MaxConcurrency || time.Duration(cfg.MaxDurationSeconds)*time.Second > profile.MaxDuration {
		return fmt.Errorf("adapters: scanner config exceeds product profile budget")
	}
	return nil
}

func validateProfileBudget(profile ProfileBudget) error {
	if profile.RequestsPerSecond < 1 || profile.RequestsPerSecond > 1000 ||
		profile.MaxConcurrency < 1 || profile.MaxConcurrency > 100 ||
		profile.MaxRequestsPerTarget < 1 || profile.MaxRequestsPerTarget > 100000 ||
		profile.MaxDuration < time.Minute || profile.MaxDuration > 24*time.Hour {
		return fmt.Errorf("adapters: invalid product profile budget")
	}
	return nil
}
