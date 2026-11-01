package pacing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacingConfigDefaultsAndCeilings(t *testing.T) {
	// 1. Defaults per scanner
	preflightCfg := DefaultConfig("http_preflight", "example.com")
	if preflightCfg.RequestsPerSecond != 2 {
		t.Fatalf("expected 2 req/s for http_preflight, got %d", preflightCfg.RequestsPerSecond)
	}

	zapCfg := DefaultConfig("zap", "example.com")
	if zapCfg.RequestsPerSecond != 1 {
		t.Fatalf("expected 1 req/s for zap, got %d", zapCfg.RequestsPerSecond)
	}

	// 2. EffectiveRate calculation
	// User requests 10, but platform ceiling is 5 and nuclei max is 5
	rate := EffectiveRate("nuclei", 10, 0)
	if rate != 5 {
		t.Fatalf("expected 5 req/s ceiling for nuclei, got %d", rate)
	}

	// User requests 10 for zap, zap ceiling is 1
	zapRate := EffectiveRate("zap", 10, 0)
	if zapRate != 1 {
		t.Fatalf("expected 1 req/s ceiling for zap, got %d", zapRate)
	}

	// Profile ceiling of 2 applies even if nuclei allows 5
	profileLimited := EffectiveRate("nuclei", 5, 2)
	if profileLimited != 2 {
		t.Fatalf("expected 2 req/s due to profile ceiling, got %d", profileLimited)
	}

	// 3. Validation
	if err := ValidateRate("zap", 2); err == nil {
		t.Fatalf("expected error when validating zap rate exceeding 1 req/s")
	}
	if err := ValidateRate("nuclei", 4); err != nil {
		t.Fatalf("unexpected error for nuclei rate 4: %v", err)
	}
	if err := ValidateRate("nuclei", 6); err == nil {
		t.Fatalf("expected error for nuclei rate 6 exceeding ceiling 5")
	}
}

func TestTokenBucketBurstAndRefill(t *testing.T) {
	cfg := Config{
		Target:            "test.example.com",
		Scanner:           "test",
		RequestsPerSecond: 10,
		BurstLimit:        3,
	}
	pacer := NewTokenBucketPacer(cfg)
	defer pacer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Initial burst: 3 tokens available immediately
	for i := 0; i < 3; i++ {
		ev, err := pacer.Acquire(ctx, "test.example.com")
		if err != nil {
			t.Fatalf("failed burst acquire %d: %v", i, err)
		}
		if ev.Throttled {
			t.Fatalf("expected burst acquire %d to not be throttled", i)
		}
	}

	// 4th token requires waiting for refill
	start := time.Now()
	ev, err := pacer.Acquire(ctx, "test.example.com")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("failed acquire 4: %v", err)
	}
	if !ev.Throttled {
		t.Fatalf("expected 4th request to be throttled")
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("expected wait duration for refill, observed %v", elapsed)
	}
}

func TestPerTargetIsolation(t *testing.T) {
	cfg := Config{
		RequestsPerSecond: 2,
		BurstLimit:        1,
	}
	pacer := NewTokenBucketPacer(cfg)
	defer pacer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Exhaust targetA
	_, err := pacer.Acquire(ctx, "targetA.com")
	if err != nil {
		t.Fatalf("acquire targetA failed: %v", err)
	}

	// targetB should still have its own separate burst token
	if !pacer.TryAcquire("targetB.com") {
		t.Fatalf("expected targetB to have independent token available")
	}

	// targetA should now be depleted
	if pacer.TryAcquire("targetA.com") {
		t.Fatalf("expected targetA to be depleted")
	}
}

func TestContextCancellationWhileThrottled(t *testing.T) {
	cfg := Config{
		RequestsPerSecond: 1,
		BurstLimit:        1,
	}
	pacer := NewTokenBucketPacer(cfg)
	defer pacer.Close()

	// Consume token
	if !pacer.TryAcquire("exhausted.com") {
		t.Fatalf("initial consume failed")
	}

	// Context with short deadline
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := pacer.Acquire(ctx, "exhausted.com")
	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
}

func TestThrottlingEventListener(t *testing.T) {
	cfg := Config{
		RequestsPerSecond: 5,
		BurstLimit:        1,
	}
	pacer := NewTokenBucketPacer(cfg)
	defer pacer.Close()

	var throttledEvents []PacingEvent
	var mu sync.Mutex

	pacer.AddListener(func(ev PacingEvent) {
		mu.Lock()
		throttledEvents = append(throttledEvents, ev)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1st request (burst)
	_, _ = pacer.Acquire(ctx, "monitored.com")

	// 2nd request (throttled)
	_, _ = pacer.Acquire(ctx, "monitored.com")

	mu.Lock()
	count := len(throttledEvents)
	mu.Unlock()

	if count != 1 {
		t.Fatalf("expected exactly 1 throttling event, observed %d", count)
	}
}

func TestPacingRoundTripperAndBackoff(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqNum := atomic.AddInt32(&requestCount, 1)
		if reqNum == 2 {
			// Trigger 429 on second request
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Rate limit exceeded"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	cfg := Config{
		RequestsPerSecond: 10,
		BurstLimit:        5,
		BackoffDuration:   100 * time.Millisecond,
		JitterEnabled:     false,
	}
	pacer := NewTokenBucketPacer(cfg)
	defer pacer.Close()

	client := &http.Client{
		Transport: NewPacingRoundTripper(http.DefaultTransport, pacer),
		Timeout:   5 * time.Second,
	}

	// 1. First request -> 200 OK
	resp1, err := client.Get(server.URL)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("request 1 failed: resp=%v err=%v", resp1, err)
	}
	_, _ = io.ReadAll(resp1.Body)
	resp1.Body.Close()

	// 2. Second request -> 429 Too Many Requests, triggers backoff
	resp2, err := client.Get(server.URL)
	if err != nil || resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 2 failed: resp=%v err=%v", resp2, err)
	}
	_, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()

	// 3. Immediately checking TryAcquire for server should fail due to backoff
	targetHost := NormalizeTarget(server.URL)
	if pacer.TryAcquire(targetHost) {
		t.Fatalf("expected pacer to be in backoff mode for %s", targetHost)
	}
}

func TestConcurrentPacingUnderLoad(t *testing.T) {
	cfg := Config{
		RequestsPerSecond: 20,
		BurstLimit:        2,
	}
	pacer := NewTokenBucketPacer(cfg)
	defer pacer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	numWorkers := 10
	requestsPerWorker := 3
	var wg sync.WaitGroup
	var completedCount int64

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < requestsPerWorker; j++ {
				_, err := pacer.Acquire(ctx, "concurrent-target.com")
				if err != nil {
					return
				}
				atomic.AddInt64(&completedCount, 1)
			}
		}(i)
	}

	wg.Wait()

	expected := int64(numWorkers * requestsPerWorker)
	if completedCount != expected {
		t.Fatalf("expected %d completed acquisitions under concurrency, got %d", expected, completedCount)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://EXAMPLE.COM:8080/path/to/resource", "example.com"},
		{"http://test.local:443/", "test.local"},
		{"TARGET.COM", "target.com"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"", "unknown"},
	}

	for _, tc := range cases {
		got := NormalizeTarget(tc.input)
		if got != tc.expected {
			t.Errorf("NormalizeTarget(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}
