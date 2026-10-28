// Package sandbox provides a fake in-memory Executor for unit tests that do not
// have a container runtime available. It simulates success, OOM kill, deadline
// exceeded, and scanner crash based on the container image/args.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// FakeExecutor is an in-memory Executor for unit tests. Configure its behavior
// with Mode and the corresponding payload.
type FakeExecutor struct {
	// Mode selects the simulated outcome: "success", "oom", "deadline",
	// "crash", or "error". Defaults to "success".
	Mode string
	// ExitCode is used when Mode is "crash".
	ExitCode int
	// Stdout/Stderr are returned on success.
	Stdout string
	Stderr string
	// Findings is returned on success as the raw findings payload.
	Findings []byte
	// Duration simulates execution time.
	Duration time.Duration
	// Err is returned when Mode is "error".
	Err error

	// LastSpec records the most recent spec passed to Execute (for assertions).
	Last Spec
}

// Execute simulates container execution. It respects ctx cancellation by
// returning ErrDeadlineExceeded when the context is already done.
func (f *FakeExecutor) Execute(ctx context.Context, spec Spec) (*Result, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return &Result{DeadlineExceeded: true, ExitCode: -1}, ErrDeadlineExceeded
	}
	f.Last = spec

	result := &Result{Duration: f.Duration, Stdout: f.Stdout, Stderr: f.Stderr, Findings: f.Findings}

	switch f.Mode {
	case "success", "":
		result.ExitCode = 0
		return result, nil
	case "oom":
		result.ExitCode = 137
		result.OOMKilled = true
		return result, &ExitError{Spec: spec, Result: result, Err: errors.New("container killed")}
	case "deadline":
		result.ExitCode = -1
		result.DeadlineExceeded = true
		return result, &ExitError{Spec: spec, Result: result, Err: ErrDeadlineExceeded}
	case "crash":
		code := f.ExitCode
		if code == 0 {
			code = 1
		}
		result.ExitCode = code
		return result, &ExitError{Spec: spec, Result: result, Err: errors.New("scanner exited non-zero")}
	case "error":
		result.ExitCode = -1
		return result, &ExitError{Spec: spec, Result: result, Err: f.Err}
	default:
		return nil, fmt.Errorf("sandbox: unknown fake mode %q", f.Mode)
	}
}
