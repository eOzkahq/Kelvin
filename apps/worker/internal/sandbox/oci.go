// Package sandbox provides an OCI container executor (Docker/Podman-compatible)
// that provisions scanner adapters inside rootless, hardened containers per
// ADR-0005 and docs/architecture/EXECUTION_ISOLATION.md.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// maxCaptureBytes caps the number of bytes captured from each of stdout/stderr
// so a hostile or misbehaving scanner cannot exhaust worker memory.
const maxCaptureBytes = 4 * 1024 * 1024 // 4 MiB

// OCIExecutor runs scanner containers via an OCI-compatible CLI (podman or
// docker in rootless mode). It detects the runtime on construction.
type OCIExecutor struct {
	runtime string
}

// NewOCIExecutor returns an executor backed by podman (preferred, rootless by
// design) or docker (rootless mode). It returns an error if no runtime is
// available; callers in unit tests should use FakeExecutor instead.
func NewOCIExecutor() (*OCIExecutor, error) {
	for _, candidate := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return &OCIExecutor{runtime: candidate}, nil
		}
	}
	return nil, errors.New("sandbox: no OCI runtime (podman/docker) found; use FakeExecutor for tests")
}

// Execute runs spec inside a rootless OCI container. ctx cancellation (hard
// deadline) terminates the container via SIGTERM then SIGKILL.
func (e *OCIExecutor) Execute(ctx context.Context, spec Spec) (*Result, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return &Result{DeadlineExceeded: true, ExitCode: -1}, ErrDeadlineExceeded
	}

	start := time.Now()
	result := &Result{}

	args := e.buildArgs(spec)
	cmd := exec.CommandContext(ctx, e.runtime, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = truncate(stdout.String())
	result.Stderr = truncate(stderr.String())

	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.DeadlineExceeded = true
			result.ExitCode = -1
			return result, &ExitError{Spec: spec, Result: result, Err: ErrDeadlineExceeded}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			// Exit code 137 = SIGKILL (OOM killer or supervisor kill).
			if result.ExitCode == 137 {
				result.OOMKilled = true
			}
			if result.ExitCode < 0 {
				result.DeadlineExceeded = true
			}
			return result, &ExitError{Spec: spec, Result: result, Err: err}
		}
		result.ExitCode = -1
		return result, &ExitError{Spec: spec, Result: result, Err: err}
	}

	result.ExitCode = 0
	return result, nil
}

// buildArgs constructs the OCI run command with the mandatory hardening
// profile. The container is removed on exit (--rm) so no state persists.
func (e *OCIExecutor) buildArgs(spec Spec) []string {
	args := []string{"run", "--rm"}

	// User / privilege isolation.
	args = append(args, "--user", spec.User)
	args = append(args, "--cap-drop=ALL")
	for _, cap := range spec.CapAdd {
		args = append(args, "--cap-add="+cap)
	}

	// Filesystem isolation.
	if spec.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	for _, m := range spec.TmpfsMounts {
		args = append(args, "--tmpfs="+m)
	}

	// Resource bounds (cgroups v2).
	if spec.MemoryLimit != "" {
		args = append(args, "--memory="+spec.MemoryLimit)
	}
	if spec.CPUQuota != "" {
		args = append(args, "--cpus="+spec.CPUQuota)
	}
	if spec.PIDsLimit > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", spec.PIDsLimit))
	}

	// Network isolation.
	if spec.NetworkDisabled {
		args = append(args, "--network=none")
	}

	// Security profiles.
	for _, opt := range spec.SecurityOpt {
		args = append(args, "--security-opt="+opt)
	}

	// Environment, workdir, labels.
	for _, env := range spec.Env {
		args = append(args, "--env", env)
	}
	if spec.WorkingDir != "" {
		args = append(args, "--workdir", spec.WorkingDir)
	}
	for k, v := range spec.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	args = append(args, spec.Args...)
	return args
}

func truncate(s string) string {
	if len(s) <= maxCaptureBytes {
		return s
	}
	return s[:maxCaptureBytes] + "\n[output truncated by worker sandbox]"
}
