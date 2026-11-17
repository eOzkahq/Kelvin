// Package limits defines enforceable resource bounds for assessment worker
// execution (P1-29, P2-24). Every sandboxed scanner job runs inside a rootless
// container provisioned against these limits; violations are logged and
// surfaced as auditable termination causes.
//
// See docs/architecture/EXECUTION_ISOLATION.md §3.5 and docs/architecture/SCANNER_RESOURCE_LIMITS.md.
package limits

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrExceedsCeiling is returned when requested limits surpass platform ceilings.
	ErrExceedsCeiling = errors.New("limits: requested resource exceeds platform ceiling")
	// ErrUnknownScanner is returned when no default limits are registered for a scanner.
	ErrUnknownScanner = errors.New("limits: unknown scanner identifier")
)

// Limits are the resource bounds applied to one sandboxed scanner execution.
// All fields are required and validated by Validate against safe maximums so a
// single assessment cannot destabilize the host.
type Limits struct {
	// CPUQuota is the cgroup CPU quota as a number of CPUs (e.g. "0.5", "1", "2.0").
	CPUQuota string `json:"cpu_quota"`
	// MemoryLimit is the cgroup memory ceiling (e.g. "128m", "512m", "1536m", "2g").
	MemoryLimit string `json:"memory_limit"`
	// MemoryHigh optionally specifies the soft memory throttling threshold (e.g. "450m").
	MemoryHigh string `json:"memory_high,omitempty"`
	// DiskLimit is the ephemeral scratch disk ceiling (e.g. "64m", "512m", "2g").
	DiskLimit string `json:"disk_limit"`
	// MaxPIDs is the cgroup pids-limit to prevent fork bombs.
	MaxPIDs int64 `json:"max_pids"`
	// MaxConcurrentConns bounds simultaneous connections to a single target.
	MaxConcurrentConns int `json:"max_concurrent_conns"`
	// MaxRequestsPerTarget bounds the total request budget per target.
	MaxRequestsPerTarget int `json:"max_requests_per_target"`
	// HardDeadline is the absolute execution deadline; the supervisor kills the
	// container (and its process tree) when it expires.
	HardDeadline time.Duration `json:"hard_deadline"`
}

// PlatformCeiling defines the absolute safe upper bounds permitted on worker nodes
// (cpu.max <= 2.0 cores, memory.max <= 2GB, pids.max <= 256, per ADR-0005 and P2-24).
var PlatformCeiling = Limits{
	CPUQuota:             "2.0",
	MemoryLimit:          "2g",
	DiskLimit:            "2g",
	MaxPIDs:              256,
	MaxConcurrentConns:   50,
	MaxRequestsPerTarget: 50000,
	HardDeadline:         30 * time.Minute,
}

// ScannerDefaultLimits maintains approved, tuned resource limits for each scanner.
var ScannerDefaultLimits = map[string]Limits{
	"http_preflight": {
		CPUQuota:             "0.5",
		MemoryLimit:          "128m",
		DiskLimit:            "64m",
		MaxPIDs:              16,
		MaxConcurrentConns:   2,
		MaxRequestsPerTarget: 1,
		HardDeadline:         2 * time.Minute,
	},
	"http_security_headers": {
		CPUQuota:             "0.5",
		MemoryLimit:          "128m",
		DiskLimit:            "64m",
		MaxPIDs:              16,
		MaxConcurrentConns:   2,
		MaxRequestsPerTarget: 10,
		HardDeadline:         2 * time.Minute,
	},
	"http_headers": {
		CPUQuota:             "0.5",
		MemoryLimit:          "128m",
		DiskLimit:            "64m",
		MaxPIDs:              16,
		MaxConcurrentConns:   2,
		MaxRequestsPerTarget: 10,
		HardDeadline:         2 * time.Minute,
	},
	"tls_assessment": {
		CPUQuota:             "0.5",
		MemoryLimit:          "256m",
		DiskLimit:            "64m",
		MaxPIDs:              16,
		MaxConcurrentConns:   2,
		MaxRequestsPerTarget: 10,
		HardDeadline:         3 * time.Minute,
	},
	"tls_assessor": {
		CPUQuota:             "0.5",
		MemoryLimit:          "256m",
		DiskLimit:            "64m",
		MaxPIDs:              16,
		MaxConcurrentConns:   2,
		MaxRequestsPerTarget: 10,
		HardDeadline:         3 * time.Minute,
	},
	"zap_baseline": {
		CPUQuota:             "2.0",
		MemoryLimit:          "1536m",
		DiskLimit:            "512m",
		MaxPIDs:              128,
		MaxConcurrentConns:   10,
		MaxRequestsPerTarget: 1000,
		HardDeadline:         10 * time.Minute,
	},
	"zap": {
		CPUQuota:             "2.0",
		MemoryLimit:          "1536m",
		DiskLimit:            "512m",
		MaxPIDs:              128,
		MaxConcurrentConns:   10,
		MaxRequestsPerTarget: 1000,
		HardDeadline:         10 * time.Minute,
	},
	"nuclei": {
		CPUQuota:             "2.0",
		MemoryLimit:          "1024m",
		DiskLimit:            "256m",
		MaxPIDs:              64,
		MaxConcurrentConns:   25,
		MaxRequestsPerTarget: 5000,
		HardDeadline:         10 * time.Minute,
	},
}

// ForScanner returns the tuned, approved resource limits for the given scanner.
// If a ceiling is specified, the scanner limits are verified to not exceed that ceiling.
func ForScanner(scannerID string, ceiling ...Limits) (Limits, error) {
	canonical := canonicalizeScanner(scannerID)
	l, ok := ScannerDefaultLimits[canonical]
	if !ok {
		return Limits{}, fmt.Errorf("%w: %q", ErrUnknownScanner, scannerID)
	}

	activeCeiling := PlatformCeiling
	if len(ceiling) > 0 && ceiling[0] != (Limits{}) {
		activeCeiling = ceiling[0]
	}

	if err := ValidateAgainstCeiling(l, activeCeiling); err != nil {
		return Limits{}, fmt.Errorf("%w for scanner %s: %v", ErrExceedsCeiling, scannerID, err)
	}
	return l, nil
}

// ValidateAgainstCeiling validates that requested limits do not exceed platform ceilings.
func ValidateAgainstCeiling(requested, ceiling Limits) error {
	var problems []string

	if requested.CPUQuota != "" && ceiling.CPUQuota != "" {
		reqCPU, err1 := ParseCPUQuota(requested.CPUQuota)
		ceilCPU, err2 := ParseCPUQuota(ceiling.CPUQuota)
		if err1 == nil && err2 == nil && reqCPU > ceilCPU {
			problems = append(problems, fmt.Sprintf("cpu_quota %s exceeds ceiling %s", requested.CPUQuota, ceiling.CPUQuota))
		}
	}

	if requested.MemoryLimit != "" && ceiling.MemoryLimit != "" {
		reqMem, err1 := ParseMemoryBytes(requested.MemoryLimit)
		ceilMem, err2 := ParseMemoryBytes(ceiling.MemoryLimit)
		if err1 == nil && err2 == nil && reqMem > ceilMem {
			problems = append(problems, fmt.Sprintf("memory_limit %s exceeds ceiling %s", requested.MemoryLimit, ceiling.MemoryLimit))
		}
	}

	if requested.DiskLimit != "" && ceiling.DiskLimit != "" {
		reqDisk, err1 := ParseMemoryBytes(requested.DiskLimit)
		ceilDisk, err2 := ParseMemoryBytes(ceiling.DiskLimit)
		if err1 == nil && err2 == nil && reqDisk > ceilDisk {
			problems = append(problems, fmt.Sprintf("disk_limit %s exceeds ceiling %s", requested.DiskLimit, ceiling.DiskLimit))
		}
	}

	if requested.MaxPIDs > 0 && ceiling.MaxPIDs > 0 && requested.MaxPIDs > ceiling.MaxPIDs {
		problems = append(problems, fmt.Sprintf("max_pids %d exceeds ceiling %d", requested.MaxPIDs, ceiling.MaxPIDs))
	}

	if requested.MaxConcurrentConns > 0 && ceiling.MaxConcurrentConns > 0 && requested.MaxConcurrentConns > ceiling.MaxConcurrentConns {
		problems = append(problems, fmt.Sprintf("max_concurrent_conns %d exceeds ceiling %d", requested.MaxConcurrentConns, ceiling.MaxConcurrentConns))
	}

	if requested.MaxRequestsPerTarget > 0 && ceiling.MaxRequestsPerTarget > 0 && requested.MaxRequestsPerTarget > ceiling.MaxRequestsPerTarget {
		problems = append(problems, fmt.Sprintf("max_requests_per_target %d exceeds ceiling %d", requested.MaxRequestsPerTarget, ceiling.MaxRequestsPerTarget))
	}

	if requested.HardDeadline > 0 && ceiling.HardDeadline > 0 && requested.HardDeadline > ceiling.HardDeadline {
		problems = append(problems, fmt.Sprintf("hard_deadline %s exceeds ceiling %s", requested.HardDeadline, ceiling.HardDeadline))
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrExceedsCeiling, strings.Join(problems, "; "))
	}
	return nil
}

// ParseMemoryBytes parses human-readable memory notation (e.g. "128m", "1g", "64k") into integer bytes.
func ParseMemoryBytes(s string) (int64, error) {
	clean := strings.TrimSpace(strings.ToLower(s))
	if clean == "" {
		return 0, errors.New("empty memory string")
	}
	unit := clean[len(clean)-1]
	mult := int64(1)
	valStr := clean
	switch unit {
	case 'k':
		mult = 1024
		valStr = clean[:len(clean)-1]
	case 'm':
		mult = 1024 * 1024
		valStr = clean[:len(clean)-1]
	case 'g':
		mult = 1024 * 1024 * 1024
		valStr = clean[:len(clean)-1]
	case 't':
		mult = 1024 * 1024 * 1024 * 1024
		valStr = clean[:len(clean)-1]
	}
	val, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil || val <= 0 {
		return 0, fmt.Errorf("invalid memory quantity %q", s)
	}
	return val * mult, nil
}

// ParseCPUQuota parses CPU quota notation (e.g. "0.5", "1", "2.0") into float64 cores.
func ParseCPUQuota(s string) (float64, error) {
	clean := strings.TrimSpace(s)
	val, err := strconv.ParseFloat(clean, 64)
	if err != nil || val <= 0 {
		return 0, fmt.Errorf("invalid cpu quota %q", s)
	}
	return val, nil
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

// Safe absolute maximums enforced at validation so no job can request unbounded
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
	} else if l.MemoryHigh != "" {
		highBytes, err1 := ParseMemoryBytes(l.MemoryHigh)
		limitBytes, err2 := ParseMemoryBytes(l.MemoryLimit)
		if err1 != nil {
			problems = append(problems, fmt.Sprintf("invalid memory_high: %v", err1))
		}
		if err2 == nil && err1 == nil && highBytes > limitBytes {
			problems = append(problems, fmt.Sprintf("memory_high %s exceeds memory_limit %s", l.MemoryHigh, l.MemoryLimit))
		}
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

func canonicalizeScanner(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
