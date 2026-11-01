package retry

import (
	"math/rand"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/classification"
)

// Default retry constants
const (
	DefaultMaxRetries        = 2
	DefaultInitialBackoff    = 1 * time.Second
	DefaultMaxBackoff        = 10 * time.Second
	DefaultBackoffMultiplier = 2.0
)

// Policy defines bounded retry behavior and exponential backoff parameters for scanner jobs.
type Policy struct {
	MaxRetries        int                              `json:"max_retries"`
	InitialBackoff    time.Duration                    `json:"initial_backoff"`
	MaxBackoff        time.Duration                    `json:"max_backoff"`
	BackoffMultiplier float64                          `json:"backoff_multiplier"`
	JitterEnabled     bool                             `json:"jitter_enabled"`
	AllowedCategories []classification.FailureCategory `json:"allowed_categories"`
	nowFn             func() time.Time
	randFn            func(n int64) int64
}

// DefaultPolicy returns a safe baseline retry policy permitting retries only for
// verified transient network reachability and infrastructure faults.
func DefaultPolicy() Policy {
	return Policy{
		MaxRetries:        DefaultMaxRetries,
		InitialBackoff:    DefaultInitialBackoff,
		MaxBackoff:        DefaultMaxBackoff,
		BackoffMultiplier: DefaultBackoffMultiplier,
		JitterEnabled:     true,
		AllowedCategories: []classification.FailureCategory{
			classification.CategoryTargetUnreachable,
			classification.CategoryInfrastructureFault,
		},
		nowFn:  time.Now,
		randFn: rand.Int63n,
	}
}

// ScannerPolicy returns tailored retry policies per scanner type.
// Heavy active scanners (e.g. ZAP, Nuclei) have strict single-retry bounds to prevent
// excessive traffic to target infrastructure, whereas light preflights permit two retries.
func ScannerPolicy(scanner string) Policy {
	p := DefaultPolicy()
	switch scanner {
	case "zap", "nuclei":
		p.MaxRetries = 1
		p.InitialBackoff = 2 * time.Second
		p.MaxBackoff = 10 * time.Second
	case "http_preflight", "http_security_headers", "tls_assessor":
		p.MaxRetries = 2
		p.InitialBackoff = 500 * time.Millisecond
		p.MaxBackoff = 3 * time.Second
	}
	return p
}

// ShouldRetry assesses whether a failed execution attempt can safely be retried.
// It verifies:
// 1. Current attempt count < MaxRetries
// 2. Failure category is explicitly marked retryable
// 3. Failure category is in policy.AllowedCategories
// 4. Backoff delay + execution buffer does not exceed the hard assessment deadline
func (p Policy) ShouldRetry(attempt int, failure classification.ClassifiedFailure, deadline time.Time) (bool, time.Duration) {
	if attempt >= p.MaxRetries {
		return false, 0
	}
	if !failure.Retryable {
		return false, 0
	}

	categoryAllowed := false
	for _, allowed := range p.AllowedCategories {
		if failure.Category == allowed {
			categoryAllowed = true
			break
		}
	}
	if !categoryAllowed {
		return false, 0
	}

	// Compute exponential backoff: initial * (multiplier ^ attempt)
	backoffSec := p.InitialBackoff.Seconds()
	multiplier := p.BackoffMultiplier
	if multiplier <= 1.0 {
		multiplier = 2.0
	}
	for i := 0; i < attempt; i++ {
		backoffSec *= multiplier
	}

	backoff := time.Duration(backoffSec * float64(time.Second))
	if backoff > p.MaxBackoff {
		backoff = p.MaxBackoff
	}

	// Apply randomized jitter if enabled (adds 0..25% of backoff)
	if p.JitterEnabled && backoff > 0 {
		maxJitter := backoff.Nanoseconds() / 4
		if maxJitter > 0 && p.randFn != nil {
			jitter := time.Duration(p.randFn(maxJitter))
			backoff += jitter
		}
	}

	// Check if backoff fits within the remaining execution deadline
	now := time.Now()
	if p.nowFn != nil {
		now = p.nowFn()
	}

	if !deadline.IsZero() {
		if now.Add(backoff).After(deadline) {
			// Backoff would exceed execution deadline
			return false, 0
		}
	}

	return true, backoff
}
