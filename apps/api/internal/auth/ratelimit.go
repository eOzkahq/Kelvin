package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
)

type clientRecord struct {
	count     int
	resetTime time.Time
}

// MemoryRateLimiter provides in-memory IP/identity sliding rate limiting for auth endpoints.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	records map[string]*clientRecord
	limit   int
	window  time.Duration
}

// NewMemoryRateLimiter creates a new rate limiter with the specified limit and time window.
func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
	limiter := &MemoryRateLimiter{
		records: make(map[string]*clientRecord),
		limit:   limit,
		window:  window,
	}

	// Periodic cleanup of stale client records
	go func() {
		ticker := time.NewTicker(window * 2)
		for range ticker.C {
			limiter.mu.Lock()
			now := time.Now()
			for k, v := range limiter.records {
				if now.After(v.resetTime) {
					delete(limiter.records, k)
				}
			}
			limiter.mu.Unlock()
		}
	}()

	return limiter
}

// Allow checks if the given key is within the rate limit.
func (l *MemoryRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	rec, exists := l.records[key]

	if !exists || now.After(rec.resetTime) {
		l.records[key] = &clientRecord{
			count:     1,
			resetTime: now.Add(l.window),
		}
		return true
	}

	if rec.count < l.limit {
		rec.count++
		return true
	}

	return false
}

// RateLimitMiddleware enforces rate limits on authentication requests (e.g. login, refresh).
func RateLimitMiddleware(limiter *MemoryRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)
			if !limiter.Allow(ip) {
				httpapi.WriteProblem(w, r, kelvinerrors.NewRateLimited("Rate limit exceeded on authentication endpoint. Please retry later."))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fallback to RemoteAddr (strip port if present)
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
