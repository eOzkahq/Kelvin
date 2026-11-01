package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxCaptureBytes = 4 * 1024 * 1024
const truncationMarker = "\n[output truncated by worker sandbox]"

type OCIExecutor struct{ runtime string }

func NewOCIExecutor() (*OCIExecutor, error) {
	for _, candidate := range []string{"podman", "docker"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return &OCIExecutor{runtime: path}, nil
		}
	}
	return nil, errors.New("sandbox: no OCI runtime (podman/docker) found")
}

func (e *OCIExecutor) Execute(ctx context.Context, spec Spec) (*Result, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return &Result{Cancelled: true, ExitCode: -1}, ErrCancelled
		}
		return &Result{DeadlineExceeded: true, ExitCode: -1}, ErrDeadlineExceeded
	}
	start := time.Now()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("sandbox: generate container name: %w", err)
	}
	containerName := "kelvin-job-" + hex.EncodeToString(nonce[:])
	args := e.buildArgs(spec)
	imageIndex := len(args) - len(spec.Invocation.Args) - 1
	namedArgs := make([]string, 0, len(args)+2)
	namedArgs = append(namedArgs, args[:imageIndex]...)
	namedArgs = append(namedArgs, "--name", containerName)
	namedArgs = append(namedArgs, args[imageIndex:]...)
	cmd := (ProcessInvocation{Executable: e.runtime, Args: namedArgs}).Command()
	cmd.Env = runtimeEnvironment()
	stdout, stderr := newBoundedBuffer(maxCaptureBytes), newBoundedBuffer(maxCaptureBytes)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		result := &Result{Duration: time.Since(start), Stdout: stdout.String(), Stderr: stderr.String()}
		if spec.CaptureZAPReport {
			if copyErr := e.captureZAPReport(containerName, result); copyErr != nil {
				e.removeContainer(containerName)
				return result, fmt.Errorf("sandbox: capture ZAP report: %w", copyErr)
			}
		}
		e.removeContainer(containerName)
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
		stop := exec.CommandContext(stopCtx, e.runtime, "stop", "--time=2", containerName)
		stop.Env = runtimeEnvironment()
		_ = stop.Run()
		cancel()
		e.removeContainer(containerName)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		cancelled := errors.Is(ctx.Err(), context.Canceled)
		result := &Result{Duration: time.Since(start), Stdout: stdout.String(), Stderr: stderr.String(), DeadlineExceeded: !cancelled, Cancelled: cancelled, ExitCode: -1}
		cause := ErrDeadlineExceeded
		if cancelled {
			cause = ErrCancelled
		}
		return result, &ExitError{Spec: spec, Result: result, Err: cause}
	}
}

func (e *OCIExecutor) buildArgs(spec Spec) []string {
	args := []string{"run"}
	if !spec.CaptureZAPReport {
		args = append(args, "--rm")
	}
	args = append(args, "--user", spec.User, "--cap-drop=ALL", "--entrypoint", spec.Invocation.Executable)
	for _, cap := range spec.CapAdd {
		args = append(args, "--cap-add="+cap)
	}
	if spec.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	for _, mount := range spec.TmpfsMounts {
		args = append(args, "--tmpfs="+mount)
	}
	if spec.WorkspaceMount != "" {
		args = append(args, "-v", spec.WorkspaceMount+":/workspace:rw")
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
	args = append(args, spec.Invocation.Args...)
	return args
}

func (e *OCIExecutor) captureZAPReport(containerName string, result *Result) error {
	dir, err := os.MkdirTemp("", "kelvin-zap-report-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	destination := filepath.Join(dir, "report.json")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"cp", containerName + ":/tmp/kelvin-zap-report.json", destination}
	cmd := exec.CommandContext(ctx, e.runtime, args...)
	cmd.Env = runtimeEnvironment()
	var stdout, stderr boundedBuffer
	stdout.maxBytes, stderr.maxBytes = 16<<10, 16<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("OCI runtime report copy failed: %w", err)
	}
	file, err := os.Open(destination)
	if err != nil {
		return err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxCaptureBytes+1))
	if err != nil {
		return err
	}
	if len(content) == 0 || len(content) > maxCaptureBytes {
		return fmt.Errorf("report is empty or exceeds %d bytes", maxCaptureBytes)
	}
	result.Findings = content
	return nil
}

func (e *OCIExecutor) removeContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.runtime, "rm", "--force", name)
	cmd.Env = runtimeEnvironment()
	_ = cmd.Run()
}

type boundedBuffer struct {
	buf       bytes.Buffer
	maxBytes  int
	truncated bool
}

func newBoundedBuffer(maxBytes int) *boundedBuffer { return &boundedBuffer{maxBytes: maxBytes} }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	limit := b.maxBytes - len(truncationMarker)
	remaining := limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	if len(p) > remaining {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	if b.truncated {
		return b.buf.String() + truncationMarker
	}
	return b.buf.String()
}

func runtimeEnvironment() []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "DOCKER_HOST": true, "DOCKER_CONFIG": true,
		"DOCKER_CERT_PATH": true, "DOCKER_TLS_VERIFY": true, "CONTAINER_HOST": true,
		"REGISTRY_AUTH_FILE": true, "XDG_RUNTIME_DIR": true,
		"SYSTEMROOT": true, "WINDIR": true, "TEMP": true, "TMP": true,
	}
	var filtered []string
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok && allowed[strings.ToUpper(key)] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

var _ io.Writer = (*boundedBuffer)(nil)
