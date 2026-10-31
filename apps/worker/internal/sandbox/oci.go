// Package sandbox provides an OCI container executor (Docker/Podman-compatible)
// that provisions scanner adapters inside rootless, hardened containers per
// ADR-0005 and docs/architecture/EXECUTION_ISOLATION.md.
//
// P1-29: each container is provisioned against enforceable resource limits
// (CPU, memory, disk, pids) and the worker supervisor terminates the entire
// process tree when the hard execution deadline expires.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// maxCaptureBytes caps the number of bytes captured from each of stdout/stderr
// so a hostile or misbehaving scanner cannot exhaust worker memory.
const maxCaptureBytes = 4 * 1024 * 1024 // 4 MiB

// gracePeriod is how long the supervisor waits after SIGTERM before SIGKILL
// when terminating a container at deadline.
const gracePeriod = 5 * time.Second

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
// deadline) terminates the container process tree via SIGTERM then SIGKILL.
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
	// Place the container runtime in its own process group so the supervisor
	// can terminate the entire process tree (runtime + container + scanner
	// descendants) on deadline or cancellation.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	// Wait for completion or context cancellation (deadline).
	select {
	case err := <-done:
		result.Duration = time.Since(start)
		result.Stdout = truncate(stdout.String())
		result.Stderr = truncate(stderr.String())
		if err == nil {
			result.ExitCode = 0
			return result, nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
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
		} else {
			result.ExitCode = -1
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			result.DeadlineExceeded = true
			return result, &ExitError{Spec: spec, Result: result, Err: ErrDeadlineExceeded}
		}
		return result, &ExitError{Spec: spec, Result: result, Err: err}
	case <-ctx.Done():
		// Terminate the entire process tree: SIGTERM then SIGKILL to the
		// process group so the container runtime and scanner descendants are
		// reaped, preventing runaway scanner subprocesses.
		terminateProcessTree(cmd)
		// Drain Run to release resources.
		<-done
		result.Duration = time.Since(start)
		result.Stdout = truncate(stdout.String())
		result.Stderr = truncate(stderr.String())
		result.DeadlineExceeded = true
		result.ExitCode = -1
		return result, &ExitError{Spec: spec, Result: result, Err: ErrDeadlineExceeded}
	}
}

// terminateProcessTree sends SIGTERM to the process group, waits the grace
// period, then SIGKills any remaining processes. This guarantees scanner
// subprocesses and the container runtime are reaped at deadline.
func terminateProcessTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		// Fall back to killing the single process.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(gracePeriod, func() { _ = cmd.Process.Kill() })
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	time.AfterFunc(gracePeriod, func() {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	})
}

// buildArgs constructs the OCI run command with the mandatory hardening
// profile and P1-29 resource limits. The container is removed on exit (--rm)
// so no state persists.

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
	// Ephemeral scratch disk ceiling (P1-29).
	if spec.Limits.DiskLimit != "" {
		args = append(args, "--storage-opt", "size="+spec.Limits.DiskLimit)
	}

	// Resource bounds (cgroups v2) from Limits (P1-29), falling back to
	// scalar fields for backward compatibility.
	if spec.Limits.MemoryLimit != "" {
		args = append(args, "--memory="+spec.Limits.MemoryLimit)
	} else if spec.MemoryLimit != "" {
		args = append(args, "--memory="+spec.MemoryLimit)
	}
	if spec.Limits.CPUQuota != "" {
		args = append(args, "--cpus="+spec.Limits.CPUQuota)
	} else if spec.CPUQuota != "" {
		args = append(args, "--cpus="+spec.CPUQuota)
	}
	pids := spec.Limits.MaxPIDs
	if pids <= 0 {
		pids = spec.PIDsLimit
	}
	if pids > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", pids))

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
