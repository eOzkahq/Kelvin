package pacing

import (
	"fmt"
	"time"
)

// Platform-enforced global limits and ceilings
const (
	PlatformMaxRateCeiling    = 5 // Absolute platform ceiling: 5 req/s for MVP
	PlatformDefaultBurstLimit = 2 // Default burst token allowance
	DefaultRatePerSecond      = 2 // Fallback default rate
)

// ScannerDefaultRates defines safe baseline request pacing rates per scanner.
var ScannerDefaultRates = map[string]int{
	"http_preflight":        2,
	"tls_assessor":          2,
	"http_security_headers": 2,
	"zap":                   1,
	"nuclei":                2,
}

// ScannerMaxCeilings defines maximum allowed rate ceilings per scanner.
var ScannerMaxCeilings = map[string]int{
	"http_preflight":        2,
	"tls_assessor":          2,
	"http_security_headers": 2,
	"zap":                   1,
	"nuclei":                5,
}

// Config specifies rate limiting and pacing parameters for a target.
type Config struct {
	Target             string        `json:"target"`
	Scanner            string        `json:"scanner"`
	RequestsPerSecond  int           `json:"requests_per_second"`
	BurstLimit         int           `json:"burst_limit"`
	BackoffDuration    time.Duration `json:"backoff_duration"`
	MaxBackoffDuration time.Duration `json:"max_backoff_duration"`
	JitterEnabled      bool          `json:"jitter_enabled"`
}

// DefaultConfig returns safe default pacing parameters for the given scanner and target.
func DefaultConfig(scanner, target string) Config {
	rate, ok := ScannerDefaultRates[scanner]
	if !ok || rate <= 0 {
		rate = DefaultRatePerSecond
	}
	burst := PlatformDefaultBurstLimit
	if rate < burst {
		burst = rate
	}
	if burst < 1 {
		burst = 1
	}

	return Config{
		Target:             target,
		Scanner:            scanner,
		RequestsPerSecond:  rate,
		BurstLimit:         burst,
		BackoffDuration:    500 * time.Millisecond,
		MaxBackoffDuration: 5 * time.Second,
		JitterEnabled:      true,
	}
}

// EffectiveRate computes the actual allowed requests-per-second, enforcing
// platform ceilings and scanner-specific limits. Users or profiles cannot exceed
// the platform ceiling or scanner ceiling.
func EffectiveRate(scanner string, requestedRPS, profileCeiling int) int {
	ceiling := PlatformMaxRateCeiling
	if scannerCap, ok := ScannerMaxCeilings[scanner]; ok && scannerCap < ceiling {
		ceiling = scannerCap
	}
	if profileCeiling > 0 && profileCeiling < ceiling {
		ceiling = profileCeiling
	}

	rate := requestedRPS
	if rate <= 0 {
		if def, ok := ScannerDefaultRates[scanner]; ok {
			rate = def
		} else {
			rate = DefaultRatePerSecond
		}
	}

	if rate > ceiling {
		return ceiling
	}
	return rate
}

// ValidateRate returns an error if requestedRPS exceeds platform ceilings or scanner limits.
func ValidateRate(scanner string, requestedRPS int) error {
	if requestedRPS < 1 {
		return fmt.Errorf("pacing: requests_per_second must be at least 1")
	}
	ceiling := PlatformMaxRateCeiling
	if scannerCap, ok := ScannerMaxCeilings[scanner]; ok && scannerCap < ceiling {
		ceiling = scannerCap
	}
	if requestedRPS > ceiling {
		return fmt.Errorf("pacing: requested rate %d req/s exceeds ceiling %d req/s for scanner %q",
			requestedRPS, ceiling, scanner)
	}
	return nil
}
