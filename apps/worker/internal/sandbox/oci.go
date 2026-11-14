package sandbox

import (
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

	"github.com/kelvin/kelvin/apps/worker/internal/outputcapture"
)

const maxCaptureBytes = outputcapture.DefaultMaxCaptureBytes

type RuntimeMetadata struct {
	Executable    string `json:"executable"`
	Version       string `json:"version,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	CgroupVersion string `json:"cgroup_version,omitempty"`
	Rootless      bool   `json:"rootless,omitempty"`
}

type OCIExecutor struct {
	runtime string
	meta    RuntimeMetadata
}

func (e *OCIExecutor) Metadata() RuntimeMetadata {
	return e.meta
}

func (e *OCIExecutor) RuntimePath() string {
	return e.runtime
}

func NewOCIExecutor() (*OCIExecutor, error) {
	for _, candidate := range []string{"podman", "docker"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return &OCIExecutor{runtime: path}, nil
		}
	}
	return nil, errors.New("sandbox: no OCI runtime (podman/docker) found")
}

// VerifyRuntime probes the discovered OCI runtime binary to verify that the
// container engine daemon/socket is responsive.
func (e *OCIExecutor) VerifyRuntime(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.runtime, "info")
	cmd.Env = runtimeEnvironment()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sandbox: OCI runtime %q daemon/socket is unavailable: %w (output: %s)", e.runtime, err, strings.TrimSpace(string(out)))
	}

	cgroupVersion := "v2"
	arch := ""
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Cgroup Version:") {
			parts := strings.Split(trimmed, ":")
			if len(parts) >= 2 {
				cgroupVersion = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(trimmed, "Architecture:") {
			parts := strings.Split(trimmed, ":")
			if len(parts) >= 2 {
				arch = strings.TrimSpace(parts[1])
			}
		}
	}

	e.meta = RuntimeMetadata{
		Executable:    e.runtime,
		CgroupVersion: cgroupVersion,
		Architecture:  arch,
	}
	return nil
}

func (e *OCIExecutor) Execute(ctx context.Context, spec Spec) (*Result, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return &Result{Cancelled: true, ExitCode: -1, LifecycleState: StateFailed}, ErrCancelled
		}
		return &Result{DeadlineExceeded: true, ExitCode: -1, LifecycleState: StateFailed}, ErrDeadlineExceeded
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
	stdout, stderr := outputcapture.NewBoundedWriter(maxCaptureBytes), outputcapture.NewBoundedWriter(maxCaptureBytes)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		result := &Result{
			Duration:        time.Since(start),
			Stdout:          stdout.String(),
			Stderr:          stderr.String(),
			StdoutBytes:     stdout.TotalBytes(),
			StderrBytes:     stderr.TotalBytes(),
			StdoutTruncated: stdout.Truncated(),
			StderrTruncated: stderr.Truncated(),
			ContainerName:   containerName,
			LifecycleState:  StateStopped,
		}
		if spec.CaptureZAPReport {
			if copyErr := e.captureZAPReport(containerName, result); copyErr != nil {
				e.removeContainer(containerName)
				result.LifecycleState = StateCleaned
				return result, fmt.Errorf("sandbox: capture ZAP report: %w", copyErr)
			}
		}
		e.removeContainer(containerName)
		result.LifecycleState = StateCleaned
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
		result.LifecycleState = StateFailed
		return result, &ExitError{Spec: spec, Result: result, Err: err}
	case <-ctx.Done():
		cancelled := errors.Is(ctx.Err(), context.Canceled)
		stopGrace := "--time=10"
		if cancelled {
			stopGrace = "--time=5"
		}
		// Grace period enforcement: issue stop with 5s (cancel) or 10s (timeout) grace period before SIGKILL
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		stop := exec.CommandContext(stopCtx, e.runtime, "stop", stopGrace, containerName)
		stop.Env = runtimeEnvironment()
		_ = stop.Run()
		cancel()
		e.removeContainer(containerName)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		result := &Result{
			Duration:         time.Since(start),
			Stdout:           stdout.String(),
			Stderr:           stderr.String(),
			StdoutBytes:      stdout.TotalBytes(),
			StderrBytes:      stderr.TotalBytes(),
			StdoutTruncated:  stdout.Truncated(),
			StderrTruncated:  stderr.Truncated(),
			DeadlineExceeded: !cancelled,
			Cancelled:        cancelled,
			ExitCode:         -1,
			ContainerName:    containerName,
			LifecycleState:   StateCleaned,
		}
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
	mem := ""
	if spec.Limits.MemoryLimit != "" {
		mem = spec.Limits.MemoryLimit
	} else if spec.MemoryLimit != "" {
		mem = spec.MemoryLimit
	}
	if mem != "" {
		args = append(args, "--memory="+mem)
		args = append(args, "--memory-swap="+mem)
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
	if spec.EgressProxy != "" {
		hasProxy := false
		for _, env := range spec.Env {
			if strings.HasPrefix(env, "HTTP_PROXY=") {
				hasProxy = true
				break
			}
		}
		if !hasProxy {
			args = append(args,
				"--env", "HTTP_PROXY="+spec.EgressProxy,
				"--env", "HTTPS_PROXY="+spec.EgressProxy,
				"--env", "http_proxy="+spec.EgressProxy,
				"--env", "https_proxy="+spec.EgressProxy,
				"--env", "KELVIN_EGRESS_PROXY="+spec.EgressProxy,
			)
		}
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
	stdout := outputcapture.NewBoundedWriter(16 << 10)
	stderr := outputcapture.NewBoundedWriter(16 << 10)
	cmd.Stdout, cmd.Stderr = stdout, stderr
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


