package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_SlidingWindowAllowAndThrottle(t *testing.T) {
	limiter := NewRateLimiter(3, 1) // Standard: 3/min, Expensive: 1/min
	key := "tenant:test-1"
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	// 1st request -> allowed (remaining: 2)
	res1 := limiter.Allow(key, OpCategoryStandard, now)
	assert.True(t, res1.Allowed)
	assert.Equal(t, 2, res1.Remaining)

	// 2nd request -> allowed (remaining: 1)
	res2 := limiter.Allow(key, OpCategoryStandard, now.Add(5*time.Second))
	assert.True(t, res2.Allowed)
	assert.Equal(t, 1, res2.Remaining)

	// 3rd request -> allowed (remaining: 0)
	res3 := limiter.Allow(key, OpCategoryStandard, now.Add(10*time.Second))
	assert.True(t, res3.Allowed)
	assert.Equal(t, 0, res3.Remaining)

	// 4th request -> throttled (exceeded limit of 3)
	res4 := limiter.Allow(key, OpCategoryStandard, now.Add(15*time.Second))
	assert.False(t, res4.Allowed)
	assert.Equal(t, 0, res4.Remaining)
	assert.Greater(t, res4.RetrySecs, 0)

	// Expensive category throttles after 1 request
	expKey := "tenant:test-1:exp"
	e1 := limiter.Allow(expKey, OpCategoryExpensive, now)
	assert.True(t, e1.Allowed)
	e2 := limiter.Allow(expKey, OpCategoryExpensive, now.Add(1*time.Second))
	assert.False(t, e2.Allowed)
}

func TestRateLimitMiddleware_HeadersAndHTTPResponse(t *testing.T) {
	limiter := NewRateLimiter(2, 1)
	handler := RateLimitMiddleware(limiter, OpCategoryStandard)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	tenantID := uuid.New()
	ctx, err := tenant.WithID(context.Background(), tenantID)
	require.NoError(t, err)

	// 1. First request -> 200 OK
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil).WithContext(ctx)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "2", rec1.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "1", rec1.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, rec1.Header().Get("X-RateLimit-Reset"))

	// 2. Second request -> 200 OK
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil).WithContext(ctx)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "0", rec2.Header().Get("X-RateLimit-Remaining"))

	// 3. Third request -> 429 Too Many Requests
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil).WithContext(ctx)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	assert.Equal(t, http.StatusTooManyRequests, rec3.Code)
	assert.NotEmpty(t, rec3.Header().Get("Retry-After"))
	assert.Contains(t, rec3.Body.String(), "Too Many Requests")
}

func TestResolveRateLimitKey_TenantSpoofingDefense(t *testing.T) {
	// Attacker tries to spoof another tenant via X-Tenant-ID header without authenticated context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/public", nil)
	req.Header.Set("X-Tenant-ID", "00000000-0000-0000-0000-000000000001")
	req.RemoteAddr = "203.0.113.195:12345"

	key := ResolveRateLimitKey(req, OpCategoryStandard)
	// Must be keyed by IP, NEVER trusting the spoofed header
	assert.Contains(t, key, "ip:203.0.113.195")
	assert.NotContains(t, key, "00000000-0000-0000-0000-000000000001")
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	limit := 10
	limiter := NewRateLimiter(limit, limit)
	key := "tenant:concurrent-test"
	now := time.Now().UTC()

	var (
		wg      sync.WaitGroup
		allowed int64
		denied  int64
	)

	// 30 concurrent requests competing for 10 slots
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := limiter.Allow(key, OpCategoryStandard, now)
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			} else {
				atomic.AddInt64(&denied, 1)
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(limit), allowed)
	assert.Equal(t, int64(20), denied)
}
