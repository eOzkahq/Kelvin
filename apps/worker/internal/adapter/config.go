// Package adapter defines the configuration schema for all supported KELVIN scanners.
//
// Every engine has a validated, typed configuration schema with enforced default
// and boundary constraints. Unsafe options (e.g., arbitrary Nuclei templates, active ZAP attacks)
// are strictly prohibited from being activated via configuration.
package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ConfigSchemaVersion is the current version of the scanner configuration schema.
const ConfigSchemaVersion = "1.0"

// Sentinel errors for configuration validation.
var (
	ErrInvalidConfigSchema = errors.New("config: unsupported configuration schema version")
	ErrUnsupportedEngine   = errors.New("config: unsupported scanner engine")
	ErrConfigOutOfRange    = errors.New("config: parameter value out of permitted range")
	ErrUnsafeConfigOption  = errors.New("config: unsafe configuration option prohibited")
)

// PreflightConfig defines settings for the built-in HTTP/HTTPS preflight probe.
type PreflightConfig struct {
	MaxRedirects      int           `json:"max_redirects"`
	FollowRedirects   bool          `json:"follow_redirects"`
	TimeoutPerRequest time.Duration `json:"timeout_per_request"`
	UserAgent         string        `json:"user_agent"`
}

// DefaultPreflightConfig returns safe default settings for preflight checks.
func DefaultPreflightConfig() PreflightConfig {
	return PreflightConfig{
		MaxRedirects:      5,
		FollowRedirects:   true,
		TimeoutPerRequest: 5 * time.Second,
		UserAgent:         "Kelvin-Assessment-Worker/1.0 (Security Scanner)",
	}
}

// Validate checks preflight configuration boundaries.
func (c PreflightConfig) Validate() error {
	if c.MaxRedirects < 0 || c.MaxRedirects > 10 {
		return fmt.Errorf("%w: max_redirects must be between 0 and 10", ErrConfigOutOfRange)
	}
	if c.TimeoutPerRequest < 1*time.Second || c.TimeoutPerRequest > 30*time.Second {
		return fmt.Errorf("%w: timeout_per_request must be between 1s and 30s", ErrConfigOutOfRange)
	}
	if strings.ContainsAny(c.UserAgent, "\r\n") {
		return fmt.Errorf("%w: user_agent cannot contain newline characters", ErrUnsafeConfigOption)
	}
	return nil
}

// TLSConfig defines settings for the built-in TLS assessor.
type TLSConfig struct {
	MinTLSVersion           string        `json:"min_tls_version"`
	CheckCipherSuites       bool          `json:"check_cipher_suites"`
	CheckCertificateExpiry  bool          `json:"check_certificate_expiry"`
	ConnectTimeout          time.Duration `json:"connect_timeout"`
}

// DefaultTLSConfig returns safe defaults for TLS assessment.
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		MinTLSVersion:          "TLS1.0",
		CheckCipherSuites:      true,
		CheckCertificateExpiry: true,
		ConnectTimeout:         10 * time.Second,
	}
}

// Validate checks TLS configuration parameters.
func (c TLSConfig) Validate() error {
	switch c.MinTLSVersion {
	case "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3":
	default:
		return fmt.Errorf("%w: invalid min_tls_version %q", ErrConfigOutOfRange, c.MinTLSVersion)
	}
	if c.ConnectTimeout < 1*time.Second || c.ConnectTimeout > 30*time.Second {
		return fmt.Errorf("%w: connect_timeout must be between 1s and 30s", ErrConfigOutOfRange)
	}
	return nil
}

// HeaderCheckConfig defines settings for HTTP security header inspection.
type HeaderCheckConfig struct {
	CheckHSTS    bool `json:"check_hsts"`
	CheckCSP     bool `json:"check_csp"`
	CheckCookies bool `json:"check_cookies"`
	CheckCORS    bool `json:"check_cors"`
}

// DefaultHeaderCheckConfig returns default inspection flags.
func DefaultHeaderCheckConfig() HeaderCheckConfig {
	return HeaderCheckConfig{
		CheckHSTS:    true,
		CheckCSP:     true,
		CheckCookies: true,
		CheckCORS:    true,
	}
}

// Validate checks header configuration.
func (c HeaderCheckConfig) Validate() error {
	return nil
}

// ZAPBaselineConfig defines settings for OWASP ZAP Baseline scanner.
type ZAPBaselineConfig struct {
	ScanMode              string   `json:"scan_mode"`
	MaxDurationSeconds    int      `json:"max_duration_seconds"`
	MaxDepth              int      `json:"max_depth"`
	SpiderDurationMinutes int      `json:"spider_duration_minutes"`
	ExcludePaths          []string `json:"exclude_paths,omitempty"`
}

// DefaultZAPBaselineConfig returns safe default settings for ZAP.
func DefaultZAPBaselineConfig() ZAPBaselineConfig {
	return ZAPBaselineConfig{
		ScanMode:              "baseline",
		MaxDurationSeconds:    300,
		MaxDepth:              2,
		SpiderDurationMinutes: 2,
	}
}

// Validate strictly prevents active scan mode or excessive duration in ZAP.
func (c ZAPBaselineConfig) Validate() error {
	if c.ScanMode != "baseline" && c.ScanMode != "passive-only" {
		return fmt.Errorf("%w: ZAP scan_mode must be 'baseline' or 'passive-only', got %q", ErrUnsafeConfigOption, c.ScanMode)
	}
	if c.MaxDurationSeconds < 30 || c.MaxDurationSeconds > 600 {
		return fmt.Errorf("%w: max_duration_seconds must be between 30 and 600", ErrConfigOutOfRange)
	}
	if c.MaxDepth < 1 || c.MaxDepth > 5 {
		return fmt.Errorf("%w: max_depth must be between 1 and 5", ErrConfigOutOfRange)
	}
	if c.SpiderDurationMinutes < 1 || c.SpiderDurationMinutes > 5 {
		return fmt.Errorf("%w: spider_duration_minutes must be between 1 and 5", ErrConfigOutOfRange)
	}
	return nil
}

// NucleiConfig defines settings for the Nuclei engine.
type NucleiConfig struct {
	CuratedCatalogOnly bool     `json:"curated_catalog_only"`
	TemplateTags       []string `json:"template_tags"`
	ExcludedTags       []string `json:"excluded_tags"`
	MaxConcurrency     int      `json:"max_concurrency"`
	RequestRateLimit   int      `json:"request_rate_limit"`
}

// DefaultNucleiConfig returns safe default configuration for Nuclei.
func DefaultNucleiConfig() NucleiConfig {
	return NucleiConfig{
		CuratedCatalogOnly: true,
		TemplateTags:       []string{"cve", "misconfig", "ssl", "tech"},
		ExcludedTags:       []string{"dos", "fuzz", "intrusive", "exploit"},
		MaxConcurrency:     10,
		RequestRateLimit:   25,
	}
}

// Validate guarantees that custom or arbitrary templates can never be executed.
func (c NucleiConfig) Validate() error {
	if !c.CuratedCatalogOnly {
		return fmt.Errorf("%w: curated_catalog_only must be true; arbitrary templates are strictly prohibited", ErrUnsafeConfigOption)
	}
	if c.MaxConcurrency < 1 || c.MaxConcurrency > 25 {
		return fmt.Errorf("%w: max_concurrency must be between 1 and 25", ErrConfigOutOfRange)
	}
	if c.RequestRateLimit < 1 || c.RequestRateLimit > 50 {
		return fmt.Errorf("%w: request_rate_limit must be between 1 and 50", ErrConfigOutOfRange)
	}
	for _, tag := range c.TemplateTags {
		if strings.ContainsAny(tag, ";|&$`\n\r") {
			return fmt.Errorf("%w: template tag %q contains invalid characters", ErrUnsafeConfigOption, tag)
		}
	}
	return nil
}

// EngineConfiguration encapsulates the root configuration envelope for any engine.
type EngineConfiguration struct {
	SchemaVersion string             `json:"schema_version"`
	Engine        string             `json:"engine"`
	Preflight     *PreflightConfig   `json:"preflight,omitempty"`
	TLS           *TLSConfig         `json:"tls,omitempty"`
	Headers       *HeaderCheckConfig `json:"headers,omitempty"`
	ZAP           *ZAPBaselineConfig `json:"zap,omitempty"`
	Nuclei        *NucleiConfig      `json:"nuclei,omitempty"`
}

// ValidateEngineConfiguration performs root validation and delegates to engine-specific validators.
func ValidateEngineConfiguration(cfg EngineConfiguration) error {
	if cfg.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrInvalidConfigSchema, cfg.SchemaVersion, ConfigSchemaVersion)
	}

	switch cfg.Engine {
	case "preflight":
		if cfg.Preflight == nil {
			return fmt.Errorf("%w: preflight configuration required", ErrMissingRequiredField)
		}
		return cfg.Preflight.Validate()
	case "tls":
		if cfg.TLS == nil {
			return fmt.Errorf("%w: tls configuration required", ErrMissingRequiredField)
		}
		return cfg.TLS.Validate()
	case "headers":
		if cfg.Headers == nil {
			return fmt.Errorf("%w: headers configuration required", ErrMissingRequiredField)
		}
		return cfg.Headers.Validate()
	case "zap":
		if cfg.ZAP == nil {
			return fmt.Errorf("%w: zap configuration required", ErrMissingRequiredField)
		}
		return cfg.ZAP.Validate()
	case "nuclei":
		if cfg.Nuclei == nil {
			return fmt.Errorf("%w: nuclei configuration required", ErrMissingRequiredField)
		}
		return cfg.Nuclei.Validate()
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedEngine, cfg.Engine)
	}
}

// NewDefaultConfiguration creates a valid default EngineConfiguration for the specified engine.
func NewDefaultConfiguration(engine string) (EngineConfiguration, error) {
	root := EngineConfiguration{
		SchemaVersion: ConfigSchemaVersion,
		Engine:        engine,
	}

	switch engine {
	case "preflight":
		c := DefaultPreflightConfig()
		root.Preflight = &c
	case "tls":
		c := DefaultTLSConfig()
		root.TLS = &c
	case "headers":
		c := DefaultHeaderCheckConfig()
		root.Headers = &c
	case "zap":
		c := DefaultZAPBaselineConfig()
		root.ZAP = &c
	case "nuclei":
		c := DefaultNucleiConfig()
		root.Nuclei = &c
	default:
		return EngineConfiguration{}, fmt.Errorf("%w: %q", ErrUnsupportedEngine, engine)
	}

	return root, nil
}
