// Package sandbox defines and validates the isolated scanner execution contract.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/limits"
)

var (
	ErrDeadlineExceeded = errors.New("sandbox: hard execution deadline exceeded")
	ErrCancelled        = errors.New("sandbox: execution cancelled")
	ErrOOMKilled        = errors.New("sandbox: container out of memory")
	ErrSpecInvalid      = errors.New("sandbox: invalid container specification")
)

type Executor interface {
	Execute(ctx context.Context, spec Spec) (*Result, error)
}

// ProcessInvocation describes one executable and its already-separated argv.
// It deliberately has no shell-string or command-line parsing representation.
type ProcessInvocation struct {
	Executable string
	Args       []string
}

const (
	maxInvocationArgs     = 64
	maxInvocationArgBytes = 4096
	maxInvocationBytes    = 16 * 1024
)

// Command constructs a process using exec argv directly. It never invokes a
// shell or reparses a command string.
func (p ProcessInvocation) Command() *exec.Cmd { return exec.Command(p.Executable, p.Args...) }

func (p ProcessInvocation) Validate() error {
	if !path.IsAbs(p.Executable) || strings.ContainsAny(p.Executable, "\x00\r\n") {
		return fmt.Errorf("sandbox: executable must be an absolute path")
	}
	base := strings.ToLower(path.Base(p.Executable))
	switch base {
	case "sh", "bash", "dash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh":
		return fmt.Errorf("sandbox: shell executables are prohibited")
	}
	if p.Executable != "/zap/zap-baseline.py" && p.Executable != "/nuclei" {
		return fmt.Errorf("sandbox: executable is not an approved scanner")
	}
	if len(p.Args) > maxInvocationArgs {
		return fmt.Errorf("sandbox: too many process arguments")
	}
	totalBytes := len(p.Executable)
	for _, arg := range p.Args {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("sandbox: process argument contains NUL")
		}
		if len(arg) > maxInvocationArgBytes {
			return fmt.Errorf("sandbox: process argument exceeds size limit")
		}
		totalBytes += len(arg)
	}
	if totalBytes > maxInvocationBytes {
		return fmt.Errorf("sandbox: process invocation exceeds size limit")
	}
	return nil
}

type Spec struct {
	Image           string
	Invocation      ProcessInvocation
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
	// CaptureZAPReport asks the executor to copy the fixed baseline JSON report
	// out of the still-running container before cleanup.
	CaptureZAPReport bool
	// WorkspaceMount specifies the host directory to bind-mount to /workspace in the container.
	WorkspaceMount string
	// EgressProxy specifies the local proxy URL to enforce scoped network egress.
	EgressProxy string
}

func (s Spec) Validate() error {
	var errs []string
	if s.Image == "" {
		errs = append(errs, "image must not be empty")
	}
	if err := s.Invocation.Validate(); err != nil {
		errs = append(errs, err.Error())
	}
	scanner := s.Labels["scanner"]
	allowedExecutables := map[string]string{"zap": "/zap/zap-baseline.py", "nuclei": "/nuclei"}
	if expected, ok := allowedExecutables[scanner]; !ok || s.Invocation.Executable != expected {
		errs = append(errs, "scanner executable is not in the worker allow-list")
	}
	if s.CaptureZAPReport && scanner != "zap" {
		errs = append(errs, "ZAP report capture is only available to the ZAP scanner")
	}
	if scanner == "zap" && !s.NetworkDisabled && s.EgressProxy == "" {
		errs = append(errs, "ZAP network access must remain disabled until scoped egress enforcement is configured")
	}
	if s.EgressProxy != "" {
		parsed, err := url.Parse(s.EgressProxy)
		if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || strings.ContainsAny(s.EgressProxy, "\x00\r\n") {
			errs = append(errs, "egress proxy must be a valid http URL without control characters")
		}
	}
	if s.CaptureZAPReport && !hasArgPair(s.Invocation.Args, "-J", "/tmp/kelvin-zap-report.json") {
		errs = append(errs, "ZAP report capture requires the fixed report path")
	}
	if s.User == "" || s.User == "root" || s.User == "0" {
		errs = append(errs, "container must run as a non-root user")
	}
	if !s.ReadOnlyRootfs {
		errs = append(errs, "root filesystem must be read-only")
	}
	if !contains(s.SecurityOpt, "no-new-privileges") {
		errs = append(errs, "no-new-privileges must be enabled")
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
	allowedEnvKeys := map[string]bool{
		"KELVIN_JOB_ID":         true,
		"KELVIN_TENANT_ID":      true,
		"KELVIN_ASSESSMENT_ID":  true,
		"KELVIN_CORRELATION_ID": true,
		"KELVIN_WORKSPACE":      true,
		"HTTP_PROXY":            true,
		"HTTPS_PROXY":           true,
		"http_proxy":            true,
		"https_proxy":           true,
		"NO_PROXY":              true,
		"no_proxy":              true,
		"KELVIN_EGRESS_PROXY":   true,
	}
	for _, entry := range s.Env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || !allowedEnvKeys[key] || strings.ContainsAny(entry, "\x00\r\n") {
			errs = append(errs, "container environment contains an unapproved variable")
			break
		}
	}
	if s.WorkspaceMount != "" {
		if !filepath.IsAbs(s.WorkspaceMount) || strings.ContainsAny(s.WorkspaceMount, "\x00\r\n") {
			errs = append(errs, "workspace mount must be an absolute path without control characters")
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("%w: %s", ErrSpecInvalid, strings.Join(errs, "; "))
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasArgPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

type Result struct {
	ExitCode         int
	Duration         time.Duration
	Stdout           string
	Stderr           string
	Findings         []byte
	OutputEnvelope   []byte
	OOMKilled        bool
	DeadlineExceeded bool
	Cancelled        bool
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
func (r *Result) IsDeadlineExceeded() bool { return r.DeadlineExceeded }
func (r *Result) IsOOM() bool              { return r.OOMKilled }

var (
	_ Executor = (*OCIExecutor)(nil)
	_ Executor = (*FakeExecutor)(nil)
)
