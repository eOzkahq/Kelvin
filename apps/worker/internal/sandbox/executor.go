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
	// Scanner identifies the scanner type (e.g., "nuclei", "zap").
	Scanner string
	// Image specifies the immutable container image reference with SHA256 digest.
	Image string
	// ImageDigest optionally specifies the standalone expected SHA256 digest.
	ImageDigest string
	// ScannerVersion optionally specifies the expected scanner binary version.
	ScannerVersion string
	// TemplateCatalogID optionally specifies the Nuclei template catalog ID.
	TemplateCatalogID string
	// TemplateCatalogDigest optionally specifies the Nuclei template catalog SHA256 digest.
	TemplateCatalogDigest string
	// Invocation describes the exact binary and argv to execute.
	Invocation ProcessInvocation
	// Env specifies the strict allowlisted environment variables (KEY=VALUE).
	Env []string
	// WorkingDir specifies the container working directory.
	WorkingDir string
	// User specifies the non-root execution identity (UID:GID).
	User string
	// MemoryLimit specifies the memory cgroup ceiling (e.g., "512m").
	MemoryLimit string
	// MemoryHigh specifies the soft memory throttling threshold (e.g., "450m").
	MemoryHigh string
	// CPUQuota specifies the CPU quota (e.g., "0.75" or "2").
	CPUQuota string
	// PIDsLimit specifies the maximum process count to prevent fork bombs.
	PIDsLimit int64
	// ReadOnlyRootfs enforces an immutable read-only root filesystem.
	ReadOnlyRootfs bool
	// TmpfsMounts specifies isolated in-memory scratch mounts.
	TmpfsMounts []string
	// CapDrop specifies Linux capabilities to drop.
	CapDrop []string
	// CapAdd specifies Linux capabilities to add (restricted).
	CapAdd []string
	// NetworkDisabled enforces complete network isolation when true.
	NetworkDisabled bool
	// SecurityOpt specifies container security options (must include no-new-privileges).
	SecurityOpt []string
	// Limits specifies formal resource limits if set.
	Limits limits.Limits
	// Deadline specifies the hard wall-clock execution deadline.
	Deadline time.Duration
	// Labels specifies arbitrary execution tracking labels.
	Labels map[string]string
	// CaptureZAPReport asks the executor to copy the fixed baseline JSON report
	// out of the still-running container before cleanup.
	CaptureZAPReport bool
	// WorkspaceMount specifies the host directory to bind-mount to /workspace in the container.
	WorkspaceMount string
	// EgressProxy specifies the internal proxy URL to enforce scoped network egress.
	EgressProxy string
}

var approvedScanners = map[string]string{
	"nuclei":       "/nuclei",
	"zap":          "/zap/zap-baseline.py",
	"zap-baseline": "/zap/zap-baseline.py",
	"sslscan":      "/usr/bin/sslscan",
	"nmap":         "/usr/bin/nmap",
	"whatweb":      "/usr/bin/whatweb",
	"subfinder":    "/usr/bin/subfinder",
}

// ScannerID resolves the effective scanner identity from Spec.Scanner or Spec.Labels["scanner"].
func (s Spec) ScannerID() string {
	if s.Scanner != "" {
		return s.Scanner
	}
	if s.Labels != nil {
		return s.Labels["scanner"]
	}
	return ""
}

func isSHA256Digest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	hash := strings.TrimPrefix(digest, "sha256:")
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isImmutableImageReference(ref string) bool {
	if ref == "" || strings.ContainsAny(ref, " \t\r\n\x00") {
		return false
	}
	parts := strings.Split(ref, "@")
	if len(parts) != 2 {
		return false
	}
	return isSHA256Digest(parts[1])
}

func (s Spec) Validate() error {
	var errs []string

	// 1. Scanner Identity & Executable Contract
	scanner := s.ScannerID()
	if scanner == "" {
		errs = append(errs, "scanner identity is required and must not be empty")
	} else if expected, ok := approvedScanners[scanner]; !ok {
		errs = append(errs, fmt.Sprintf("unknown scanner identity %q is rejected", scanner))
	} else if s.Invocation.Executable != expected {
		errs = append(errs, fmt.Sprintf("scanner executable %q is not approved for scanner %q", s.Invocation.Executable, scanner))
	}

	// 2. Invocation argv validation
	if err := s.Invocation.Validate(); err != nil {
		errs = append(errs, err.Error())
	}

	// 3. Immutable Image Reference & Digest Contract
	if s.Image == "" {
		errs = append(errs, "image must not be empty")
	} else if !isImmutableImageReference(s.Image) {
		errs = append(errs, "image reference must be immutable with a valid sha256 digest (e.g. image@sha256:...)")
	} else if s.ImageDigest != "" {
		if !isSHA256Digest(s.ImageDigest) {
			errs = append(errs, "image digest must be a valid sha256 hash")
		} else {
			_, refDigest, _ := strings.Cut(s.Image, "@")
			if refDigest != s.ImageDigest {
				errs = append(errs, "image reference digest does not match declared image digest")
			}
		}
	}

	// 4. Template Catalog Validation (Nuclei)
	if s.TemplateCatalogDigest != "" {
		if !isSHA256Digest(s.TemplateCatalogDigest) {
			errs = append(errs, "template catalog digest must be a valid sha256 hash")
		}
		if scanner != "nuclei" {
			errs = append(errs, "template catalog digest is only applicable to the Nuclei scanner")
		}
	}
	if s.TemplateCatalogID != "" && scanner != "nuclei" {
		errs = append(errs, "template catalog is only applicable to the Nuclei scanner")
	}

	// 5. Network Mode & Egress Enforcement
	if !s.NetworkDisabled && s.EgressProxy == "" {
		errs = append(errs, "network-enabled execution requires an enforced egress policy")
	}
	if s.EgressProxy != "" {
		parsed, err := url.Parse(s.EgressProxy)
		if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || strings.ContainsAny(s.EgressProxy, "\x00\r\n") {
			errs = append(errs, "egress proxy must be a valid http URL without control characters")
		}
	}

	// 6. ZAP Specific Constraints
	if s.CaptureZAPReport && scanner != "zap" && scanner != "zap-baseline" {
		errs = append(errs, "ZAP report capture is only available to the ZAP scanner")
	}
	if s.CaptureZAPReport && !hasArgPair(s.Invocation.Args, "-J", "/tmp/kelvin-zap-report.json") {
		errs = append(errs, "ZAP report capture requires the fixed report path")
	}

	// 7. Non-Root Execution
	if s.User == "" || s.User == "root" || s.User == "0" || strings.HasPrefix(s.User, "0:") {
		errs = append(errs, "container must run as a non-root user")
	} else {
		// Verify UID is not a system account (< 1000)
		uidPart := strings.Split(s.User, ":")[0]
		var uid int
		if _, err := fmt.Sscanf(uidPart, "%d", &uid); err == nil && uid < 1000 {
			errs = append(errs, fmt.Sprintf("container user UID %d is a reserved system user; unprivileged UID >= 1000 required", uid))
		}
	}

	// 8. Filesystem & Privilege Escalation
	if !s.ReadOnlyRootfs {
		errs = append(errs, "root filesystem must be read-only")
	}
	hasNoNewPrivs := false
	for _, opt := range s.SecurityOpt {
		if opt == "no-new-privileges" || opt == "no-new-privileges:true" {
			hasNoNewPrivs = true
			break
		}
	}
	if !hasNoNewPrivs {
		errs = append(errs, "no-new-privileges must be enabled")
	}

	// 9. Resource & Deadline Limits
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

	// 10. Prohibited Mounts & Capabilities
	if len(s.CapDrop) == 0 || !contains(s.CapDrop, "ALL") {
		errs = append(errs, "all Linux capabilities must be dropped (cap-drop=ALL required)")
	}
	for _, mount := range s.TmpfsMounts {
		dest := strings.TrimSpace(strings.Split(mount, ":")[0])
		switch dest {
		case "/", "/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/dev", "/proc", "/sys", "/root":
			errs = append(errs, fmt.Sprintf("tmpfs mount target %q is prohibited", dest))
		}
		if strings.Contains(mount, "/var/run/docker.sock") || strings.Contains(mount, "docker.sock") {
			errs = append(errs, "docker socket mount is prohibited")
		}
	}
	for _, cap := range s.CapAdd {
		upper := strings.ToUpper(cap)
		if upper != "NET_RAW" && upper != "CAP_NET_RAW" {
			errs = append(errs, fmt.Sprintf("capability %q is prohibited; only NET_RAW is permitted when authorized", cap))
		}
	}

	// 11. Strict Environment Variable Allowlist
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
			errs = append(errs, fmt.Sprintf("container environment contains an unapproved variable %q", key))
			break
		}
	}

	// 12. Workspace Path
	if s.WorkspaceMount != "" {
		if (!filepath.IsAbs(s.WorkspaceMount) && !path.IsAbs(s.WorkspaceMount)) || strings.ContainsAny(s.WorkspaceMount, "\x00\r\n") {
			errs = append(errs, "workspace mount must be an absolute path without control characters")
		}
		cleanUnix := path.Clean(strings.ReplaceAll(s.WorkspaceMount, "\\", "/"))
		cleanWin := filepath.Clean(s.WorkspaceMount)
		switch cleanUnix {
		case "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/var/run", "/proc", "/sys", "/dev", "/boot", "/root":
			errs = append(errs, fmt.Sprintf("host directory %q cannot be mounted as workspace", s.WorkspaceMount))
		}
		switch cleanWin {
		case "C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)":
			errs = append(errs, fmt.Sprintf("host directory %q cannot be mounted as workspace", s.WorkspaceMount))
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

// LifecycleState describes explicit container execution states.
type LifecycleState string

const (
	StateCreated  LifecycleState = "CREATED"
	StateStarted  LifecycleState = "STARTED"
	StateRunning  LifecycleState = "RUNNING"
	StateStopping LifecycleState = "STOPPING"
	StateStopped  LifecycleState = "STOPPED"
	StateFailed   LifecycleState = "FAILED"
	StateCleaned  LifecycleState = "CLEANED"
)

type Result struct {
	ExitCode         int
	Duration         time.Duration
	Stdout           string
	Stderr           string
	StdoutBytes      int64
	StderrBytes      int64
	StdoutTruncated  bool
	StderrTruncated  bool
	Findings         []byte
	OutputEnvelope   []byte
	OOMKilled        bool
	PIDLimitExceeded bool
	DeadlineExceeded bool
	Cancelled        bool
	LifecycleState   LifecycleState
	ContainerName    string
}

type ExitError struct {
	Spec   Spec
	Result *Result
	Err    error
}

func (e *ExitError) Error() string {
	if e.Result != nil {
		return fmt.Sprintf("sandbox: image=%s exit=%d oom=%v pid_exhausted=%v deadline=%v: %v", e.Spec.Image, e.Result.ExitCode, e.Result.OOMKilled, e.Result.PIDLimitExceeded, e.Result.DeadlineExceeded, e.Err)
	}
	return fmt.Sprintf("sandbox: image=%s: %v", e.Spec.Image, e.Err)
}
func (e *ExitError) Unwrap() error          { return e.Err }
func (r *Result) IsDeadlineExceeded() bool  { return r.DeadlineExceeded }
func (r *Result) IsOOM() bool               { return r.OOMKilled }
func (r *Result) IsPIDExhausted() bool      { return r.PIDLimitExceeded }

var (
	_ Executor = (*OCIExecutor)(nil)
	_ Executor = (*FakeExecutor)(nil)
)
