// Package metrics provides Prometheus-compatible operational counters and
// gauges for the worker daemon: resource-limit violations, termination
// causes, and job outcomes. These are auditable signals used to detect
// runaway or hostile scanner behavior (P1-29).
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// TerminationCause classifies why a sandboxed job stopped running.
type TerminationCause string

const (
	CauseCompleted   TerminationCause = "completed"
	CauseDeadline    TerminationCause = "deadline_exceeded"
	CauseCancelled   TerminationCause = "cancelled"
	CauseOOM         TerminationCause = "oom_killed"
	CauseCrash       TerminationCause = "scanner_crash"
	CauseValidation  TerminationCause = "findings_validation_failed"
	CauseSpecInvalid TerminationCause = "sandbox_spec_invalid"
	CauseNetwork     TerminationCause = "egress_blocked"
	CauseUnspecified TerminationCause = "unspecified"
)

// ViolationType classifies a resource-limit violation.
type ViolationType string

const (
	ViolationDeadline    ViolationType = "deadline_exceeded"
	ViolationOOM         ViolationType = "out_of_memory"
	ViolationCPU         ViolationType = "cpu_throttled"
	ViolationDisk        ViolationType = "disk_exceeded"
	ViolationPIDs        ViolationType = "pids_limit"
	ViolationNetwork     ViolationType = "egress_blocked"
	ViolationConcurrency ViolationType = "concurrency_exceeded"
)

// Registry maintains operational metrics for the worker daemon.
type Registry struct {
	mu sync.RWMutex

	// counters keyed by violation type
	resourceViolations map[ViolationType]uint64
	// counters keyed by termination cause
	terminations map[TerminationCause]uint64
	activeJobs   int64
	startTime    time.Time
}

var defaultRegistry = &Registry{
	resourceViolations: map[ViolationType]uint64{},
	terminations:       map[TerminationCause]uint64{},
	startTime:          time.Now().UTC(),
}

// Default returns the process-wide worker metrics registry.
func Default() *Registry {
	return defaultRegistry
}

// IncResourceViolation increments the counter for a resource-limit violation.
func (r *Registry) IncResourceViolation(v ViolationType) {
	r.mu.Lock()
	r.resourceViolations[v]++
	r.mu.Unlock()
}

// IncTermination increments the counter for a job termination cause.
func (r *Registry) IncTermination(c TerminationCause) {
	r.mu.Lock()
	r.terminations[c]++
	r.mu.Unlock()
}

// IncActiveJobs increments the current gauge of running scan jobs.
func (r *Registry) IncActiveJobs() {
	atomic.AddInt64(&r.activeJobs, 1)
}

// DecActiveJobs decrements the active scan jobs gauge.
func (r *Registry) DecActiveJobs() {
	atomic.AddInt64(&r.activeJobs, -1)
}

// Snapshot is a point-in-time metrics capture.
type Snapshot struct {
	UptimeSeconds      uint64                      `json:"uptime_seconds"`
	ActiveJobs         int64                       `json:"active_jobs"`
	ResourceViolations map[ViolationType]uint64    `json:"resource_violations"`
	Terminations       map[TerminationCause]uint64 `json:"terminations"`
}

// Snapshot returns current metric values.
func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	violations := make(map[ViolationType]uint64, len(r.resourceViolations))
	for k, v := range r.resourceViolations {
		violations[k] = v
	}
	terminations := make(map[TerminationCause]uint64, len(r.terminations))
	for k, v := range r.terminations {
		terminations[k] = v
	}
	return Snapshot{
		UptimeSeconds:      uint64(time.Since(r.startTime).Seconds()),
		ActiveJobs:         atomic.LoadInt64(&r.activeJobs),
		ResourceViolations: violations,
		Terminations:       terminations,
	}
}

// Handler emits Prometheus text-format metrics.
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		snap := r.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, "# HELP kelvin_worker_uptime_seconds Worker process uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE kelvin_worker_uptime_seconds counter\n")
		fmt.Fprintf(w, "kelvin_worker_uptime_seconds %d\n\n", snap.UptimeSeconds)

		fmt.Fprintf(w, "# HELP kelvin_worker_active_jobs Current number of active scan jobs\n")
		fmt.Fprintf(w, "# TYPE kelvin_worker_active_jobs gauge\n")
		fmt.Fprintf(w, "kelvin_worker_active_jobs %d\n\n", snap.ActiveJobs)

		for v, n := range snap.ResourceViolations {
			fmt.Fprintf(w, "# HELP kelvin_worker_resource_violations_total Resource-limit violations (%s)\n", v)
			fmt.Fprintf(w, "# TYPE kelvin_worker_resource_violations_total counter\n")
			fmt.Fprintf(w, `kelvin_worker_resource_violations_total{violation="%s"} %d`+"\n", v, n)
		}
		for c, n := range snap.Terminations {
			fmt.Fprintf(w, "# HELP kelvin_worker_job_terminations_total Job terminations (%s)\n", c)
			fmt.Fprintf(w, "# TYPE kelvin_worker_job_terminations_total counter\n")
			fmt.Fprintf(w, `kelvin_worker_job_terminations_total{cause="%s"} %d`+"\n", c, n)
		}
	}
}
