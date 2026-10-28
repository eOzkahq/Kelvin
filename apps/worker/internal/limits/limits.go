// Package limits defines enforceable resource bounds for assessment worker
// execution (P1-29). Every sandboxed scanner job runs inside a rootless
// container provisioned against these limits; violations are logged and
// surfaced as auditable termination causes.
//
// See docs/architecture/EXECUTION_ISOLATION.md §3.5 and the P1-29 resource
// control model.
package limits

import (
	"fmt"
	"strings"
	"time"
)

// Limits are the resource bounds applied to one sandboxed scanner execution.
// All fields are required and validated by Validate against safe maximums so a
// single assessment cannot destabilize the host.
type Limits struct {
	// CPUQuota is the cgroup CPU quota as a number of CPUs (e.g. "1", "2.5").
	CPUQuota string
	// MemoryLimit is the cgroup memory ceiling (e.g. "512m", "1g").
	MemoryLimit string
	// DiskLimit is the ephemeral scratch disk ceiling (e.g. "2g", "10g").
	DiskLimit string
	// MaxPIDs is the cgroup pids-limit to prevent fork bombs.
	MaxPIDs int64
	// MaxConcurrentConns bounds simultaneous connections to a single target.
	MaxConcurrentConns int
	// MaxRequestsPerTarget bounds the total request budget per target.
	MaxRequestsPerTarget int
	// HardDeadline is the absolute execution deadline; the supervisor kills the
	// container (and its process tree) when it expires.
	HardDeadline time.Duration
}

// DefaultLimits returns conservative Phase 1 defaults (SCAN_PROFILES.md
// execution_budget bounds). Workers may override from configuration.
func DefaultLimits() Limits {
	return Limits{
		CPUQuota:             "1",
		MemoryLimit:          "512m",
		DiskLimit:            "2g",
		MaxPIDs:              64,
		MaxConcurrentConns:   10,
		MaxRequestsPerTarget: 5000,
		HardDeadline:         30 * time.Minute,
	}
}

// Safe maximums enforced at validation so no job can request unbounded
// resources. Tuned for a single worker node; operators may raise them via
// configuration review.
const (
	MaxCPUQuota          = "8"
	MaxMemoryLimit       = "8g"
	MaxDiskLimit         = "50g"
	MaxPIDLimit          = 1024
	MaxConcurrentConns   = 100
	MaxRequestsPerTarget = 100000
	MaxHardDeadline      = 24 * time.Hour
	MinHardDeadline      = 1 * time.Minute
)

// Validate fails closed: it rejects empty/invalid values and any limit
// exceeding the safe maximums. A zero duration deadline is always invalid.
func (l Limits) Validate() error {
	var problems []string
	if l.CPUQuota == "" {
		problems = append(problems, "cpu_quota must not be empty")
	}
	if l.MemoryLimit == "" {
		problems = append(problems, "memory_limit must not be empty")
	}
	if l.DiskLimit == "" {
		problems = append(problems, "disk_limit must not be empty")
	}
	if l.MaxPIDs <= 0 {
		problems = append(problems, "max_pids must be positive")
	}
	if l.MaxPIDs > MaxPIDLimit {
		problems = append(problems, fmt.Sprintf("max_pids %d exceeds maximum %d", l.MaxPIDs, MaxPIDLimit))
	}
	if l.MaxConcurrentConns < 0 {
		problems = append(problems, "max_concurrent_conns must not be negative")
	}
	if l.MaxConcurrentConns > MaxConcurrentConns {
		problems = append(problems, fmt.Sprintf("max_concurrent_conns %d exceeds maximum %d", l.MaxConcurrentConns, MaxConcurrentConns))
	}
	if l.MaxRequestsPerTarget < 0 {
		problems = append(problems, "max_requests_per_target must not be negative")
	}
	if l.MaxRequestsPerTarget > MaxRequestsPerTarget {
		problems = append(problems, fmt.Sprintf("max_requests_per_target %d exceeds maximum %d", l.MaxRequestsPerTarget, MaxRequestsPerTarget))
	}
	if l.HardDeadline <= 0 {
		problems = append(problems, "hard_deadline must be positive")
	}
	if l.HardDeadline < MinHardDeadline {
		problems = append(problems, fmt.Sprintf("hard_deadline %s below minimum %s", l.HardDeadline, MinHardDeadline))
	}
	if l.HardDeadline > MaxHardDeadline {
		problems = append(problems, fmt.Sprintf("hard_deadline %s exceeds maximum %s", l.HardDeadline, MaxHardDeadline))
	}
	if len(problems) > 0 {
		return fmt.Errorf("limits: %s", strings.Join(problems, "; "))
	}
	return nil
}

// String returns a single-line summary suitable for logs and audit records.
func (l Limits) String() string {
	return fmt.Sprintf("cpu=%s mem=%s disk=%s pids=%d conns=%d reqs/target=%d deadline=%s",
		l.CPUQuota, l.MemoryLimit, l.DiskLimit, l.MaxPIDs, l.MaxConcurrentConns,
		l.MaxRequestsPerTarget, l.HardDeadline)
}
