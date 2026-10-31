// Package sandbox defines and validates the isolated scanner execution contract.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/limits"
)

var (
	ErrDeadlineExceeded = errors.New("sandbox: hard execution deadline exceeded")
	ErrOOMKilled        = errors.New("sandbox: container out of memory")
	ErrSpecInvalid      = errors.New("sandbox: invalid container specification")
)

type Executor interface {
	Execute(ctx context.Context, spec Spec) (*Result, error)
}

type Spec struct {
	Image           string
	Command         []string
	Args            []string
	Env             []string
	WorkingDir      string
	User            string
	MemoryLimit     string
	CPUQuota        string
	PIDsLimit       int64
	ReadOnlyRootfs  bool
	TmpfsMounts     []string
	CapDrop         []string
	CapAdd          []string
	NetworkDisabled bool
	SecurityOpt     []string
	Limits          limits.Limits
	Deadline        time.Duration
	Labels          map[string]string
}

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
	if s.Limits != (limits.Limits{}) {
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
	if len(errs) != 0 {
		return fmt.Errorf("%w: %s", ErrSpecInvalid, strings.Join(errs, "; "))
	}
	return nil
}

type Result struct {
	ExitCode         int
	Duration         time.Duration
	Stdout           string
	Stderr           string
	Findings         []byte
	OOMKilled        bool
	DeadlineExceeded bool
}

type ExitError struct {
	Spec   Spec
	Result *Result
	Err    error
}

func (e *ExitError) Error() string {
	if e.Result != nil {
		return fmt.Sprintf("sandbox: image=%s exit=%d oom=%v deadline=%v: %v", e.Spec.Image, e.Result.ExitCode, e.Result.OOMKilled, e.Result.DeadlineExceeded, e.Err)
	}
	return fmt.Sprintf("sandbox: image=%s: %v", e.Spec.Image, e.Err)
}
func (e *ExitError) Unwrap() error         { return e.Err }
func (r *Result) IsDeadlineExceeded() bool { return r.DeadlineExceeded || r.ExitCode < 0 }
func (r *Result) IsOOM() bool              { return r.OOMKilled }

var (
	_ Executor = (*OCIExecutor)(nil)
	_ Executor = (*FakeExecutor)(nil)
)
