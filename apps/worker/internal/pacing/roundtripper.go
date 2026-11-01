package pacing

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// PacingRoundTripper intercepts outbound HTTP requests, enforces per-target pacing,
// and automatically inspects responses for rate-limiting signals (429, 503, Retry-After).
type PacingRoundTripper struct {
	Base  http.RoundTripper
	Pacer Pacer
}

// NewPacingRoundTripper wraps an existing RoundTripper with per-target request pacing.
func NewPacingRoundTripper(base http.RoundTripper, pacer Pacer) *PacingRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &PacingRoundTripper{
		Base:  base,
		Pacer: pacer,
	}
}

// RoundTrip acquires a pacing token before delegating to the base RoundTripper.
func (rt *PacingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.Pacer != nil && req.URL != nil {
		target := req.URL.Hostname()
		if target == "" {
			target = req.Host
		}

		_, err := rt.Pacer.Acquire(req.Context(), target)
		if err != nil {
			return nil, fmt.Errorf("pacing: request rejected by target pacer: %w", err)
		}
	}

	resp, err := rt.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Detect upstream backoff signals (HTTP 429 Too Many Requests or 503 Service Unavailable)
	if rt.Pacer != nil && resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		target := req.URL.Hostname()
		if target == "" {
			target = req.Host
		}

		delay := ParseRetryAfter(resp.Header.Get("Retry-After"))
		rt.Pacer.ReportBackoff(target, delay)
	}

	return resp, nil
}

// ParseRetryAfter attempts to parse a Retry-After header as seconds or HTTP date.
func ParseRetryAfter(headerVal string) time.Duration {
	if headerVal == "" {
		return 0
	}

	// Try integer seconds
	if secs, err := strconv.Atoi(headerVal); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}

	// Try HTTP-date
	if t, err := http.ParseTime(headerVal); err == nil {
		wait := time.Until(t)
		if wait > 0 {
			return wait
		}
	}

	return 0
}
