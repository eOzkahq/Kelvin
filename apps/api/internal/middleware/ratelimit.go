package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

const (
	OpCategoryStandard  = "STANDARD"
	OpCategoryExpensive = "EXPENSIVE"

	DefaultStandardLimitPerMinute  = 100
	DefaultExpensiveLimitPerMinute = 10
	DefaultBurstCapacity           = 20
)

// RateLimitResult conveys evaluation details and HTTP response header data.
type RateLimitResult struct {
	Allowed   bool
	Limit     int
	Remaining int
	ResetAt   time.Time
	RetrySecs int
}

// RateLimiter implements an in-memory sliding window rate limiter.
type RateLimiter struct {
	mu            sync.Mutex
	windows       map[string][]time.Time
	windowSize    time.Duration
	standardLimit int
	expensiveLimit int
}

// NewRateLimiter constructs a rate limiter with configurable standard and expensive request limits.
func NewRateLimiter(standardLimit, expensiveLimit int) *RateLimiter {
	if standardLimit <= 0 {
		standardLimit = DefaultStandardLimitPerMinute
	}
	if expensiveLimit <= 0 {
		expensiveLimit = DefaultExpensiveLimitPerMinute
	}
	return &RateLimiter{
		windows:        make(map[string][]time.Time),
		windowSize:     time.Minute,
		standardLimit:  standardLimit,
		expensiveLimit: expensiveLimit,
	}
}

// Allow evaluates a request within its sliding window and returns result metrics.
func (l *RateLimiter) Allow(key string, category string, now time.Time) RateLimitResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	limit := l.standardLimit
	if category == OpCategoryExpensive {
		limit = l.expensiveLimit
	}

	windowStart := now.Add(-l.windowSize)
	timestamps := l.windows[key]

	// Prune timestamps older than sliding window
	var validTimestamps []time.Time
	for _, t := range timestamps {
		if t.After(windowStart) {
			validTimestamps = append(validTimestamps, t)
		}
	}

	currentCount := len(validTimestamps)
	resetAt := now.Add(l.windowSize)
	if len(validTimestamps) > 0 {
		resetAt = validTimestamps[0].Add(l.windowSize)
	}

	if currentCount >= limit {
		retrySecs := int(resetAt.Sub(now).Seconds())
		if retrySecs < 1 {
			retrySecs = 1
		}
		l.windows[key] = validTimestamps
		return RateLimitResult{
			Allowed:   false,
			Limit:     limit,
			Remaining: 0,
			ResetAt:   resetAt,
			RetrySecs: retrySecs,
		}
	}

	validTimestamps = append(validTimestamps, now)
	l.windows[key] = validTimestamps

	remaining := limit - len(validTimestamps)
	if remaining < 0 {
		remaining = 0
	}

	return RateLimitResult{
		Allowed:   true,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
		RetrySecs: 0,
	}
}

// ExtractClientIP retrieves client IP address from RemoteAddr or proxy headers.
func ExtractClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	return r.RemoteAddr
}

// ResolveRateLimitKey constructs a trusted subject identifier isolating tenant boundaries.
// Never trusts spoofed client headers for tenant identification.
func ResolveRateLimitKey(r *http.Request, category string) string {
	var subject string
	if tenantID, err := tenant.ID(r.Context()); err == nil && tenantID != uuid.Nil {
		subject = "tenant:" + tenantID.String()
	} else {
		// Fallback to client IP for unauthenticated public endpoints
		subject = "ip:" + ExtractClientIP(r)
	}
	return fmt.Sprintf("%s:%s", subject, category)
}

// RateLimitMiddleware returns an HTTP middleware enforcing sliding-window rate limits.
func RateLimitMiddleware(limiter *RateLimiter, category string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ResolveRateLimitKey(r, category)
			result := limiter.Allow(key, category, time.Now().UTC())

			// Standardized RFC 6585 rate limit response headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(result.RetrySecs))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":       "Too Many Requests",
					"message":     "API rate limit exceeded. Please retry after designated interval.",
					"retry_after": result.RetrySecs,
					"limit":       result.Limit,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
