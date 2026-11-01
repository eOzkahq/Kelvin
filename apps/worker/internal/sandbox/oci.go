package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const maxCaptureBytes = 4 * 1024 * 1024

type OCIExecutor struct{ runtime string }

func NewOCIExecutor() (*OCIExecutor, error) {
	for _, candidate := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return &OCIExecutor{runtime: candidate}, nil
		}
	}
	return nil, errors.New("sandbox: no OCI runtime (podman/docker) found")
}

func (e *OCIExecutor) Execute(ctx context.Context, spec Spec) (*Result, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return &Result{DeadlineExceeded: true, ExitCode: -1}, ErrDeadlineExceeded
	}
	start := time.Now()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("sandbox: generate container name: %w", err)
	}
	containerName := "kelvin-job-" + hex.EncodeToString(nonce[:])
	args := e.buildArgs(spec)
	imageIndex := len(args) - len(spec.Command) - len(spec.Args) - 1
	namedArgs := make([]string, 0, len(args)+2)
	namedArgs = append(namedArgs, args[:imageIndex]...)
	namedArgs = append(namedArgs, "--name", containerName)
	namedArgs = append(namedArgs, args[imageIndex:]...)
	cmd := exec.Command(e.runtime, namedArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		result := &Result{Duration: time.Since(start), Stdout: truncate(stdout.String()), Stderr: truncate(stderr.String())}
		if err == nil {
			return result, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			result.OOMKilled = result.ExitCode == 137
		} else {
			result.ExitCode = -1
		}
		return result, &ExitError{Spec: spec, Result: result, Err: err}
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(stopCtx, e.runtime, "stop", "--time=2", containerName).Run()
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		result := &Result{Duration: time.Since(start), Stdout: truncate(stdout.String()), Stderr: truncate(stderr.String()), DeadlineExceeded: true, ExitCode: -1}
		return result, &ExitError{Spec: spec, Result: result, Err: ErrDeadlineExceeded}
	}
}

func (e *OCIExecutor) buildArgs(spec Spec) []string {
	args := []string{"run", "--rm", "--user", spec.User, "--cap-drop=ALL"}
	for _, cap := range spec.CapAdd {
		args = append(args, "--cap-add="+cap)
	}
	if spec.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	for _, mount := range spec.TmpfsMounts {
		args = append(args, "--tmpfs="+mount)
	}
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
		args = append(args, "--pids-limit", fmt.Sprint(pids))
	}
	if spec.NetworkDisabled {
		args = append(args, "--network=none")
	}
	for _, opt := range spec.SecurityOpt {
		args = append(args, "--security-opt="+opt)
	}
	for _, env := range spec.Env {
		args = append(args, "--env", env)
	}
	if spec.WorkingDir != "" {
		args = append(args, "--workdir", spec.WorkingDir)
	}
	for key, value := range spec.Labels {
		args = append(args, "--label", key+"="+value)
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
