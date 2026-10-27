// Package metrics provides Prometheus-compatible operational metric counters and gauges
// for monitoring HTTP control plane traffic, active scanner jobs, error rates, and queue latencies.
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Registry maintains operational in-memory metrics.
type Registry struct {
	mu           sync.RWMutex
	httpRequests uint64
	httpErrors   uint64
	activeJobs   int64
	completedJobs uint64
	failedJobs   uint64
	startTime    time.Time
}

var defaultRegistry = &Registry{
	startTime: time.Now().UTC(),
}

// Default returns the process-wide metrics registry.
func Default() *Registry {
	return defaultRegistry
}

// IncRequests increments total HTTP requests handled.
func (r *Registry) IncRequests() {
	atomic.AddUint64(&r.httpRequests, 1)
}

// IncErrors increments total HTTP 5xx or server errors.
func (r *Registry) IncErrors() {
	atomic.AddUint64(&r.httpErrors, 1)
}

// IncActiveJobs increments the current gauge of running/queued scan jobs.
func (r *Registry) IncActiveJobs() {
	atomic.AddInt64(&r.activeJobs, 1)
}

// DecActiveJobs decrements the active scan jobs gauge.
func (r *Registry) DecActiveJobs() {
	atomic.AddInt64(&r.activeJobs, -1)
}

// IncCompletedJobs increments completed assessment jobs.
func (r *Registry) IncCompletedJobs() {
	atomic.AddUint64(&r.completedJobs, 1)
}

// IncFailedJobs increments failed assessment jobs.
func (r *Registry) IncFailedJobs() {
	atomic.AddUint64(&r.failedJobs, 1)
}

// Snapshot represents a point-in-time metrics capture.
type Snapshot struct {
	UptimeSeconds uint64 `json:"uptime_seconds"`
	HTTPRequests  uint64 `json:"http_requests_total"`
	HTTPErrors    uint64 `json:"http_errors_total"`
	ActiveJobs    int64  `json:"active_jobs"`
	CompletedJobs uint64 `json:"completed_jobs_total"`
	FailedJobs    uint64 `json:"failed_jobs_total"`
}

// Snapshot returns the current metric values.
func (r *Registry) Snapshot() Snapshot {
	return Snapshot{
		UptimeSeconds: uint64(time.Since(r.startTime).Seconds()),
		HTTPRequests:  atomic.LoadUint64(&r.httpRequests),
		HTTPErrors:    atomic.LoadUint64(&r.httpErrors),
		ActiveJobs:    atomic.LoadInt64(&r.activeJobs),
		CompletedJobs: atomic.LoadUint64(&r.completedJobs),
		FailedJobs:    atomic.LoadUint64(&r.failedJobs),
	}
}

// Handler returns an HTTP handler emitting Prometheus text format metrics.
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		snap := r.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, "# HELP kelvin_uptime_seconds Process uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE kelvin_uptime_seconds counter\n")
		fmt.Fprintf(w, "kelvin_uptime_seconds %d\n\n", snap.UptimeSeconds)

		fmt.Fprintf(w, "# HELP kelvin_http_requests_total Total HTTP requests handled\n")
		fmt.Fprintf(w, "# TYPE kelvin_http_requests_total counter\n")
		fmt.Fprintf(w, "kelvin_http_requests_total %d\n\n", snap.HTTPRequests)

		fmt.Fprintf(w, "# HELP kelvin_http_errors_total Total HTTP error responses (5xx)\n")
		fmt.Fprintf(w, "# TYPE kelvin_http_errors_total counter\n")
		fmt.Fprintf(w, "kelvin_http_errors_total %d\n\n", snap.HTTPErrors)

		fmt.Fprintf(w, "# HELP kelvin_jobs_active Current number of active/queued scanning jobs\n")
		fmt.Fprintf(w, "# TYPE kelvin_jobs_active gauge\n")
		fmt.Fprintf(w, "kelvin_jobs_active %d\n\n", snap.ActiveJobs)

		fmt.Fprintf(w, "# HELP kelvin_jobs_completed_total Total scanner jobs completed successfully\n")
		fmt.Fprintf(w, "# TYPE kelvin_jobs_completed_total counter\n")
		fmt.Fprintf(w, "kelvin_jobs_completed_total %d\n\n", snap.CompletedJobs)

		fmt.Fprintf(w, "# HELP kelvin_jobs_failed_total Total scanner jobs that failed or timed out\n")
		fmt.Fprintf(w, "# TYPE kelvin_jobs_failed_total counter\n")
		fmt.Fprintf(w, "kelvin_jobs_failed_total %d\n", snap.FailedJobs)
	}
}

