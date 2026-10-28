// Package sandbox provides the execution-isolation contract for running scanner
// adapters (Nmap, Nuclei, OpenVAS, Trivy, ...) inside controlled, rootless OCI
// containers. Scanner execution is fully decoupled from the API control plane:
// the worker daemon provisions a disposable container per job, enforces the
// hard execution deadline, and treats all scanner output as untrusted.
//
// See docs/architecture/EXECUTION_ISOLATION.md for the normative architecture.
// ADR-0005 governs the container hardening profile (rootless, dropped caps,
// read-only rootfs, seccomp/AppArmor, cgroups bounds).
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/limits"
)

// ErrDeadlineExceeded is returned when container execution is terminated by the
// worker supervisor at the hard execution deadline.
var ErrDeadlineExceeded = errors.New("sandbox: hard execution deadline exceeded")

// ErrOOMKilled is returned when the container is terminated by the OOM killer.
var ErrOOMKilled = errors.New("sandbox: container out of memory")

// ErrSpecInvalid is returned when a container specification violates the
// mandatory isolation profile (e.g. privileged mode, root execution).
var ErrSpecInvalid = errors.New("sandbox: invalid container specification")

// Executor provisions and runs a scanner inside an isolated container. The
// worker daemon abstracts the container runtime behind this interface so the
// runtime can migrate (Docker -> Podman -> gVisor/Kata) without changing
// scanner adapter code (ADR-0005 §7).
type Executor interface {
	// Execute runs spec inside an isolated container. ctx carries the hard
	// deadline; cancellation or deadline expiry must terminate the container.
	// A non-nil error is returned for executor/infrastructure failures; the
	// Result (when non-nil) always carries the observed exit code and signals.
	Execute(ctx context.Context, spec Spec) (*Result, error)
}

// Spec describes the isolated container in which one scanner adapter runs.
// All fields are validated by Validate; the zero value is invalid.
type Spec struct {
	// Image is the versioned, signed scanner adapter container image.
	Image string
	// Command is the container entrypoint (scanner adapter wrapper).
	Command []string
	// Args are the scanner invocation flags derived from the scan profile.
	Args []string
	// Env are environment variables passed to the container. Secrets must not
	// be placed here; scanner credentials are scoped to the target and handled
	// by the worker egress path, not the container environment.
	Env []string
	// WorkingDir is the container working directory.
	WorkingDir string
	// User is the non-root user the container runs as (uid != 0).
	User string

	// Resource bounds (cgroups v2).
	MemoryLimit string // e.g. "512m"
	CPUQuota    string // e.g. "2" (2 CPUs)
	PIDsLimit   int64  // max processes; 0 means use a safe default

	// Filesystem isolation.
	ReadOnlyRootfs bool
	// TmpfsMounts are "destination:options" strings, e.g. "/tmp:noexec,size=64m".
	TmpfsMounts []string

	// Capability control. CapDrop defaults to ALL; CapAdd is empty unless a
	// scanner demonstrably requires a capability (security review required).
	CapDrop []string
	CapAdd  []string

	// Network isolation. NetworkDisabled blocks all container networking;
	// otherwise egress is allow-listed by the runtime/egress proxy.
	NetworkDisabled bool

	// SecurityOpt are runtime security options (seccomp/AppArmor profiles).
	SecurityOpt []string

	// Limits are the enforceable resource bounds (CPU, memory, disk, pids,
	// deadline) applied to the container. They override the individual fields
	// above when set; the supervisor kills the container (and its process
	// tree) when the HardDeadline expires.
	Limits limits.Limits

	// Deadline is the hard execution deadline; the supervisor kills the
	// container when ctx is cancelled at this time.
	Deadline time.Duration

	// Labels for observability/auditing (job id, tenant id, scanner).
	Labels map[string]string
}

// Validate enforces the mandatory isolation profile. It fails closed on any
// violation: root execution, privileged mode, host socket mounts, or missing
// bounds.
func (s Spec) Validate() error {
	var errs []string
	if s.Image == "" {
		errs = append(errs, "image must not be empty")
	}
	if len(s.Command) == 0 {
		errs = append(errs, "command must not be empty")
	}
	if s.User == "" || s.User == "root" || s.User == "0" {
		errs = append(errs, "container must run as a non-root user")
	}
	if !s.ReadOnlyRootfs {
		errs = append(errs, "root filesystem must be read-only")
	}
	// If Limits are set, validate them against safe maximums; otherwise fall
	// back to the individual scalar fields.
	if (limits.Limits{} != s.Limits) {
		if err := s.Limits.Validate(); err != nil {
			errs = append(errs, err.Error())
		}
	} else {
		if s.PIDsLimit <= 0 {
			errs = append(errs, "pids-limit must be positive")
		}
		if s.Deadline <= 0 {
			errs = append(errs, "hard execution deadline must be positive")
		}
	if s.PIDsLimit <= 0 {
		errs = append(errs, "pids-limit must be positive")
	}
	if s.Deadline <= 0 {
		errs = append(errs, "hard execution deadline must be positive")
	}
	for _, mount := range s.TmpfsMounts {
		if strings.Contains(mount, "/var/run/docker.sock") {
			errs = append(errs, "docker socket mount is prohibited")
		}
	}
	for _, cap := range s.CapAdd {
		if cap == "ALL" || cap == "CAP_SYS_ADMIN" || cap == "CAP_SYS_PTRACE" {
			errs = append(errs, fmt.Sprintf("capability %q is prohibited", cap))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrSpecInvalid, strings.Join(errs, "; "))
	}
	return nil
}

// Result is the observed outcome of one container execution. All scanner
// output (Stdout/Stderr/Findings) is treated as untrusted: size-capped and
// schema-validated before ingestion.
type Result struct {
	// ExitCode is the container exit code (negative if killed by signal).
	ExitCode int
	// Duration is the wall-clock execution time.
	Duration time.Duration
	// Stdout/Stderr are size-capped captured streams (untrusted).
	Stdout string
	Stderr string
	// Findings is the raw scanner output payload (untrusted; schema validation
	// is performed by the worker/Findings Service before ingestion).
	Findings []byte
	// OOMKilled is true if the container was terminated by the OOM killer.
	OOMKilled bool
	// DeadlineExceeded is true if the supervisor terminated the container at
	// the hard execution deadline.
	DeadlineExceeded bool
}

// ExitError wraps a failed container execution with the observed result so the
// worker can distinguish infrastructure failure from scanner failure.
type ExitError struct {
	Spec   Spec
	Result *Result
	Err    error
}

func (e *ExitError) Error() string {
	if e.Result != nil {
		return fmt.Sprintf("sandbox: image=%s exit=%d oom=%v deadline=%v: %v",
			e.Spec.Image, e.Result.ExitCode, e.Result.OOMKilled, e.Result.DeadlineExceeded, e.Err)
	}
	return fmt.Sprintf("sandbox: image=%s: %v", e.Spec.Image, e.Err)
}

// Unwrap exposes the underlying error.
func (e *ExitError) Unwrap() error { return e.Err }

// IsDeadlineExceeded reports whether the execution was terminated by the hard
// deadline, allowing the worker to map to job.TIMED_OUT.
func (r *Result) IsDeadlineExceeded() bool {
	return r.DeadlineExceeded || r.ExitCode < 0
}

// IsOOM reports whether the container was killed by the OOM killer.
func (r *Result) IsOOM() bool {
	return r.OOMKilled
}

// Ensure Executor is implemented by *OCIExecutor and *FakeExecutor at compile time.
var (
	_ Executor = (*OCIExecutor)(nil)
	_ Executor = (*FakeExecutor)(nil)
)
