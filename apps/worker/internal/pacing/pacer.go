package pacing

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	ErrContextCancelled = errors.New("pacing: context cancelled while waiting for pacing token")
	ErrPacerClosed      = errors.New("pacing: pacer is closed")
)

// PacingEvent captures diagnostic information about request pacing and throttling.
type PacingEvent struct {
	Target       string        `json:"target"`
	Scanner      string        `json:"scanner"`
	Rate         int           `json:"rate"`
	WaitDuration time.Duration `json:"wait_duration"`
	Throttled    bool          `json:"throttled"`
	Timestamp    time.Time     `json:"timestamp"`
}

// ThrottlingListener receives notifications when outbound requests are throttled.
type ThrottlingListener func(event PacingEvent)

// Pacer governs the dispatch rate of requests to target destinations.
type Pacer interface {
	// Acquire blocks until a token is available or context cancels.
	Acquire(ctx context.Context, target string) (PacingEvent, error)
	// TryAcquire attempts to immediately consume a token without blocking.
	TryAcquire(target string) bool
	// ReportBackoff signals that the target returned a 429 or 503, triggering backoff with jitter.
	ReportBackoff(target string, suggestedDelay time.Duration)
	// AddListener attaches a listener for diagnostic throttling events.
	AddListener(listener ThrottlingListener)
	// Close releases resources.
	Close() error
}

// targetBucket maintains token bucket state for a single target destination.
type targetBucket struct {
	mu           sync.Mutex
	rate         float64 // tokens per second
	burst        float64 // maximum token capacity
	tokens       float64 // currently available tokens
	lastRefill   time.Time
	backoffUntil time.Time
}

// TokenBucketPacer implements per-target token-bucket pacing across multiple destinations.
type TokenBucketPacer struct {
	mu        sync.RWMutex
	buckets   map[string]*targetBucket
	defaultCfg Config
	listeners []ThrottlingListener
	closed    bool
	nowFn     func() time.Time
	randFn    func(n int64) int64
}

// NewTokenBucketPacer provisions a thread-safe token bucket pacer.
func NewTokenBucketPacer(defaultCfg Config) *TokenBucketPacer {
	if defaultCfg.RequestsPerSecond <= 0 {
		defaultCfg.RequestsPerSecond = DefaultRatePerSecond
	}
	if defaultCfg.BurstLimit <= 0 {
		defaultCfg.BurstLimit = PlatformDefaultBurstLimit
	}
	if defaultCfg.BackoffDuration <= 0 {
		defaultCfg.BackoffDuration = 500 * time.Millisecond
	}
	if defaultCfg.MaxBackoffDuration <= 0 {
		defaultCfg.MaxBackoffDuration = 5 * time.Second
	}

	return &TokenBucketPacer{
		buckets:    make(map[string]*targetBucket),
		defaultCfg: defaultCfg,
		nowFn:      time.Now,
		randFn:     rand.Int63n,
	}
}

// NormalizeTarget strips port numbers and normalizes hostname/IP casing.
func NormalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		// Just parse hostname if full URL provided
		parts := strings.SplitN(raw, "://", 2)
		raw = parts[1]
	}
	// Strip path if present
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	// Check for host:port
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(raw)
}

func (p *TokenBucketPacer) getOrCreateBucket(target string) (*targetBucket, error) {
	norm := NormalizeTarget(target)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPacerClosed
	}

	b, exists := p.buckets[norm]
	if !exists {
		b = &targetBucket{
			rate:       float64(p.defaultCfg.RequestsPerSecond),
			burst:      float64(p.defaultCfg.BurstLimit),
			tokens:     float64(p.defaultCfg.BurstLimit), // start full
			lastRefill: p.nowFn(),
		}
		p.buckets[norm] = b
	}
	return b, nil
}

// Acquire blocks until an execution slot is available for the specified target.
func (p *TokenBucketPacer) Acquire(ctx context.Context, target string) (PacingEvent, error) {
	b, err := p.getOrCreateBucket(target)
	if err != nil {
		return PacingEvent{}, err
	}

	norm := NormalizeTarget(target)
	event := PacingEvent{
		Target:    norm,
		Scanner:   p.defaultCfg.Scanner,
		Rate:      p.defaultCfg.RequestsPerSecond,
		Timestamp: p.nowFn(),
	}

	for {
		if ctx.Err() != nil {
			return event, ErrContextCancelled
		}

		b.mu.Lock()
		now := p.nowFn()

		// 1. Refill tokens based on elapsed duration
		elapsed := now.Sub(b.lastRefill).Seconds()
		b.lastRefill = now
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}

		// 2. Check backoff status
		var backoffWait time.Duration
		if b.backoffUntil.After(now) {
			backoffWait = b.backoffUntil.Sub(now)
		}

		// 3. Check token availability
		if backoffWait == 0 && b.tokens >= 1.0 {
			b.tokens -= 1.0
			b.mu.Unlock()

			if event.Throttled {
				p.notifyListeners(event)
			}
			return event, nil
		}

		// 4. Calculate required sleep duration
		var waitDuration time.Duration
		if backoffWait > 0 {
			waitDuration = backoffWait
		} else {
			deficit := 1.0 - b.tokens
			waitSec := deficit / b.rate
			waitDuration = time.Duration(waitSec * float64(time.Second))
		}
		b.mu.Unlock()

		if waitDuration < time.Millisecond {
			waitDuration = time.Millisecond
		}

		event.Throttled = true
		event.WaitDuration += waitDuration

		timer := time.NewTimer(waitDuration)
		select {
		case <-ctx.Done():
			timer.Stop()
			return event, ErrContextCancelled
		case <-timer.C:
			// Loop and try acquiring again
		}
	}
}

// TryAcquire attempts to immediately consume a token without blocking.
func (p *TokenBucketPacer) TryAcquire(target string) bool {
	b, err := p.getOrCreateBucket(target)
	if err != nil {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := p.nowFn()
	if b.backoffUntil.After(now) {
		return false
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// ReportBackoff signals that the target returned a 429 or 503, delaying subsequent requests.
func (p *TokenBucketPacer) ReportBackoff(target string, suggestedDelay time.Duration) {
	b, err := p.getOrCreateBucket(target)
	if err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := p.nowFn()
	delay := suggestedDelay
	if delay <= 0 {
		delay = p.defaultCfg.BackoffDuration
	}

	// Add jitter if enabled
	if p.defaultCfg.JitterEnabled && delay > 0 {
		jitterMax := delay.Nanoseconds() / 4
		if jitterMax > 0 {
			jitter := time.Duration(p.randFn(jitterMax))
			delay += jitter
		}
	}

	if delay > p.defaultCfg.MaxBackoffDuration {
		delay = p.defaultCfg.MaxBackoffDuration
	}

	targetBackoff := now.Add(delay)
	if targetBackoff.After(b.backoffUntil) {
		b.backoffUntil = targetBackoff
	}
}

// AddListener attaches a callback for throttling events.
func (p *TokenBucketPacer) AddListener(listener ThrottlingListener) {
	if listener == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners = append(p.listeners, listener)
}

func (p *TokenBucketPacer) notifyListeners(event PacingEvent) {
	p.mu.RLock()
	listeners := append([]ThrottlingListener(nil), p.listeners...)
	p.mu.RUnlock()

	for _, l := range listeners {
		l(event)
	}
}

// Close closes the pacer and prevents new acquisitions.
func (p *TokenBucketPacer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
