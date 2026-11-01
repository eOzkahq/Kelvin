package concurrency

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrCapacityUnavailable indicates all available concurrency slots are currently in use.
	ErrCapacityUnavailable = errors.New("concurrency: execution capacity unavailable")
	// ErrInvalidPolicy indicates an invalid concurrency configuration.
	ErrInvalidPolicy = errors.New("concurrency: invalid concurrency policy")
	// ErrLeaseNotFound indicates the referenced lease does not exist or has expired.
	ErrLeaseNotFound = errors.New("concurrency: lease not found")
)

// Policy defines multi-tiered concurrency limits and lease bounds for worker execution.
type Policy struct {
	// GlobalLimit is the platform-wide maximum number of simultaneous scanner executions.
	GlobalLimit int `json:"global_limit"`

	// PerTenantLimit is the maximum simultaneous scanner executions allowed for a single tenant.
	PerTenantLimit int `json:"per_tenant_limit"`

	// ScannerLimits defines maximum concurrent executions for specific scanner types.
	ScannerLimits map[string]int `json:"scanner_limits"`

	// DefaultLeaseTTL is the duration a slot lease remains valid without a heartbeat.
	// Guarantees crashed workers do not permanently consume slots.
	DefaultLeaseTTL time.Duration `json:"default_lease_ttl"`

	// WaitTimeout is the maximum time a job may block waiting for an available slot before failing.
	WaitTimeout time.Duration `json:"wait_timeout"`
}

// DefaultScannerLimits defines approved, safe concurrency limits per scanner.
var DefaultScannerLimits = map[string]int{
	"http_preflight":        10,
	"http_security_headers": 10,
	"http_headers":          10,
	"tls_assessment":        10,
	"tls_assessor":          10,
	"nuclei":                2, // Nuclei is active and high-load; tightly bound
	"zap-baseline":          1, // ZAP is heavyweight; bound to 1 per worker
}

// DefaultPolicy constructs a tuned, production-safe concurrency policy.
func DefaultPolicy() Policy {
	scannerLimits := make(map[string]int, len(DefaultScannerLimits))
	for k, v := range DefaultScannerLimits {
		scannerLimits[k] = v
	}
	return Policy{
		GlobalLimit:     10,
		PerTenantLimit:  3,
		ScannerLimits:   scannerLimits,
		DefaultLeaseTTL: 60 * time.Second,
		WaitTimeout:     10 * time.Second,
	}
}

// Validate ensures the policy has positive, safe bounds.
func (p Policy) Validate() error {
	if p.GlobalLimit <= 0 {
		return fmt.Errorf("%w: global limit must be positive", ErrInvalidPolicy)
	}
	if p.PerTenantLimit <= 0 {
		return fmt.Errorf("%w: per-tenant limit must be positive", ErrInvalidPolicy)
	}
	if p.PerTenantLimit > p.GlobalLimit {
		return fmt.Errorf("%w: per-tenant limit (%d) cannot exceed global limit (%d)", ErrInvalidPolicy, p.PerTenantLimit, p.GlobalLimit)
	}
	for scanner, limit := range p.ScannerLimits {
		if limit <= 0 {
			return fmt.Errorf("%w: scanner %q limit must be positive", ErrInvalidPolicy, scanner)
		}
		if limit > p.GlobalLimit {
			return fmt.Errorf("%w: scanner %q limit (%d) cannot exceed global limit (%d)", ErrInvalidPolicy, scanner, limit, p.GlobalLimit)
		}
	}
	if p.DefaultLeaseTTL <= 0 {
		return fmt.Errorf("%w: default lease TTL must be positive", ErrInvalidPolicy)
	}
	return nil
}

// LimitForScanner returns the concurrency limit for the specified scanner.
func (p Policy) LimitForScanner(scanner string) int {
	if limit, ok := p.ScannerLimits[scanner]; ok && limit > 0 {
		return limit
	}
	// Fall back to per-tenant or global limit if scanner-specific limit is unset
	if p.PerTenantLimit > 0 {
		return p.PerTenantLimit
	}
	return p.GlobalLimit
}
