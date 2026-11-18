package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
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
	OCIRuntime    string `json:"oci_runtime,omitempty"`
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
	if explicit := os.Getenv("KELVIN_OCI_RUNTIME"); explicit != "" {
		if path, err := exec.LookPath(explicit); err == nil {
			return &OCIExecutor{runtime: path}, nil
		}
		return nil, fmt.Errorf("sandbox: specified KELVIN_OCI_RUNTIME %q not found", explicit)
	}
	for _, candidate := range []string{"podman", "docker"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return &OCIExecutor{runtime: path}, nil
		}
	}
	return nil, errors.New("sandbox: no OCI runtime (podman/docker) found")
}

type podmanInfoOutput struct {
	Host struct {
		Arch          string `json:"arch"`
		CgroupVersion string `json:"cgroupVersion"`
		OCIRuntime    struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"ociRuntime"`
		Security struct {
			Rootless bool `json:"rootless"`
		} `json:"security"`
	} `json:"host"`
}

// VerifyRuntime probes the discovered OCI runtime binary to verify that the
// container engine daemon/socket is responsive.
func (e *OCIExecutor) VerifyRuntime(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// 1. First probe: check responsiveness
	cmd := exec.CommandContext(ctx, e.runtime, "info")
	cmd.Env = runtimeEnvironment()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sandbox: OCI runtime %q daemon/socket is unavailable: %w (output: %s)", e.runtime, err, strings.TrimSpace(string(out)))
	}

	cgroupVersion := ""
	arch := ""
	ociRuntime := ""
	rootless := false

	// 2. Try JSON inspect for structured Podman metadata
	jsonCmd := exec.CommandContext(ctx, e.runtime, "info", "--format", "json")
	jsonCmd.Env = runtimeEnvironment()
	if jsonOut, jsonErr := jsonCmd.Output(); jsonErr == nil {
		var pInfo podmanInfoOutput
		if json.Unmarshal(jsonOut, &pInfo) == nil {
			if pInfo.Host.CgroupVersion != "" {
				cgroupVersion = pInfo.Host.CgroupVersion
			}
			if pInfo.Host.Arch != "" {
				arch = pInfo.Host.Arch
			}
			if pInfo.Host.OCIRuntime.Name != "" {
				ociRuntime = pInfo.Host.OCIRuntime.Name
			}
			rootless = pInfo.Host.Security.Rootless
		}
	}

	// 3. Fallback: Parse line-by-line if JSON did not populate all fields
	if arch == "" || ociRuntime == "" || cgroupVersion == "" {
		for _, line := range strings.Split(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "cgroup version:") || strings.HasPrefix(lower, "cgroupversion:") {
				parts := strings.Split(trimmed, ":")
				if len(parts) >= 2 {
					cgroupVersion = strings.TrimSpace(parts[1])
				}
			}
			if strings.HasPrefix(lower, "architecture:") || strings.HasPrefix(lower, "arch:") {
				parts := strings.Split(trimmed, ":")
				if len(parts) >= 2 {
					arch = strings.TrimSpace(parts[1])
				}
			}
			if strings.HasPrefix(lower, "rootless:") {
				parts := strings.Split(trimmed, ":")
				if len(parts) >= 2 && strings.TrimSpace(parts[1]) == "true" {
					rootless = true
				}
			}
			if (strings.HasPrefix(lower, "name:") || strings.HasPrefix(lower, "ociruntime:")) && strings.Contains(lower, "crun") {
				ociRuntime = "crun"
			}
		}
	}

	e.meta = RuntimeMetadata{
		Executable:    e.runtime,
		CgroupVersion: cgroupVersion,
		Architecture:  arch,
		OCIRuntime:    ociRuntime,
		Rootless:      rootless,
	}
	return nil
}

// VerifyRootlessPodman verifies that the runtime is specifically unprivileged Rootless Podman
// backed by crun and cgroups v2 on the target architecture, as mandated by ADR-0008.
func (e *OCIExecutor) VerifyRootlessPodman(ctx context.Context) error {
	if err := e.VerifyRuntime(ctx); err != nil {
		return err
	}
	base := strings.ToLower(filepath.Base(e.runtime))
	if !strings.Contains(base, "podman") {
		return fmt.Errorf("sandbox: ADR-0008 requires rootless podman; discovered runtime is %q", e.runtime)
	}
	if !e.meta.Rootless {
		return fmt.Errorf("sandbox: ADR-0008 requires rootless container execution; podman is running as root")
	}
	if e.meta.CgroupVersion != "v2" && e.meta.CgroupVersion != "2" {
		return fmt.Errorf("sandbox: ADR-0008 requires cgroups v2; runtime reported cgroups %q (missing or unsupported)", e.meta.CgroupVersion)
	}
	if e.meta.OCIRuntime != "crun" {
		return fmt.Errorf("sandbox: ADR-0008 requires crun OCI runtime; runtime reported %q (missing or unsupported)", e.meta.OCIRuntime)
	}
	if os.Getuid() == 0 {
		return fmt.Errorf("sandbox: worker daemon must not execute as root (UID 0); dedicated unprivileged user required")
	}
	return nil
}

type networkInspectRecord struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
	Subnets  []struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	} `json:"subnets"`
}

// VerifyScannerNetwork verifies that the dedicated internal scanner network exists and is configured
// with internal=true, subnet 10.89.10.0/24, and gateway 10.89.10.1.
func (e *OCIExecutor) VerifyScannerNetwork(ctx context.Context, networkName string) error {
	if networkName == "" {
		networkName = os.Getenv("KELVIN_SCANNER_NETWORK")
		if networkName == "" {
			networkName = "kelvin-scanner-net"
		}
	}
	if networkName == "podman" || networkName == "pasta" || networkName == "host" || os.Getenv("KELVIN_ALLOW_INSECURE_RUNTIME") == "true" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.runtime, "network", "inspect", networkName, "--format", "json")
	cmd.Env = runtimeEnvironment()
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback without --format json in case format flag varies
		cmdFallback := exec.CommandContext(ctx, e.runtime, "network", "inspect", networkName)
		cmdFallback.Env = runtimeEnvironment()
		outFallback, errFallback := cmdFallback.CombinedOutput()
		if errFallback != nil {
			return fmt.Errorf("sandbox: internal scanner network %q is unavailable or does not exist: %w (output: %s)", networkName, err, strings.TrimSpace(string(out)))
		}
		out = outFallback
	}

	// Try JSON unmarshal (can be array or single object)
	var records []networkInspectRecord
	if err := json.Unmarshal(out, &records); err != nil {
		var single networkInspectRecord
		if errSingle := json.Unmarshal(out, &single); errSingle == nil {
			records = []networkInspectRecord{single}
		}
	}

	if len(records) > 0 {
		rec := records[0]
		if !rec.Internal {
			return fmt.Errorf("sandbox: scanner network %q must have internal=true to prevent direct egress bypass", networkName)
		}
		hasSubnet := false
		hasGateway := false
		for _, s := range rec.Subnets {
			if s.Subnet == "10.89.10.0/24" {
				hasSubnet = true
			}
			if s.Gateway == "10.89.10.1" {
				hasGateway = true
			}
		}
		if !hasSubnet || !hasGateway {
			return fmt.Errorf("sandbox: scanner network %q misconfigured: required subnet 10.89.10.0/24 and gateway 10.89.10.1 not found", networkName)
		}
		return nil
	}

	// String fallback validation
	outStr := string(out)
	if !strings.Contains(outStr, `"internal": true`) && !strings.Contains(outStr, `Internal: true`) && !strings.Contains(outStr, `"Internal": true`) {
		return fmt.Errorf("sandbox: scanner network %q must have internal=true to prevent direct egress bypass", networkName)
	}
	if !strings.Contains(outStr, "10.89.10.0/24") || !strings.Contains(outStr, "10.89.10.1") {
		return fmt.Errorf("sandbox: scanner network %q misconfigured: required subnet 10.89.10.0/24 and gateway 10.89.10.1 not found", networkName)
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
	args := e.buildArgsWithName(spec, containerName)
	filteredArgs := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "--security-opt=apparmor=") {
			if _, err := os.Stat("/sys/kernel/security/apparmor"); err != nil {
				continue
			}
		}
		if strings.HasPrefix(a, "--security-opt=seccomp=") {
			p := strings.TrimPrefix(a, "--security-opt=seccomp=")
			if _, err := os.Stat(p); err != nil {
				continue
			}
		}
		filteredArgs = append(filteredArgs, a)
	}
	cmd := (ProcessInvocation{Executable: e.runtime, Args: filteredArgs}).Command()
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
			if copyErr := e.captureZAPReport(containerName, result, spec); copyErr != nil {
				e.removeContainer(containerName)
				result.LifecycleState = StateCleaned
				if err != nil {
					return result, &ExitError{Spec: spec, Result: result, Err: err}
				}
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
			stderrLower := strings.ToLower(result.Stderr)
			stdoutLower := strings.ToLower(result.Stdout)
			result.OOMKilled = result.ExitCode == 137 ||
				strings.Contains(stderrLower, "out of memory") ||
				strings.Contains(stderrLower, "oom") ||
				strings.Contains(stdoutLower, "out of memory")
			result.PIDLimitExceeded = strings.Contains(stderrLower, "resource temporarily unavailable") ||
				strings.Contains(stderrLower, "can't fork") ||
				strings.Contains(stderrLower, "unable to create new native thread") ||
				strings.Contains(stdoutLower, "resource temporarily unavailable") ||
				strings.Contains(stdoutLower, "can't fork")
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
	return e.buildArgsWithName(spec, "")
}

func (e *OCIExecutor) buildArgsWithName(spec Spec, containerName string) []string {
	args := []string{"run"}
	if containerName != "" {
		args = append(args, "--name", containerName)
	}
	if !spec.CaptureZAPReport {
		args = append(args, "--rm")
	}
	user := spec.User
	if user == "" {
		user = "10001:10001"
	}
	entrypoint := spec.Invocation.Executable
	if (spec.Scanner == "nuclei" || strings.Contains(entrypoint, "nuclei")) && entrypoint == "/nuclei" {
		entrypoint = "/usr/local/bin/nuclei"
	}
	args = append(args, "--user", user, "--cap-drop=ALL", "--entrypoint", entrypoint)
	for _, cap := range spec.CapAdd {
		args = append(args, "--cap-add="+cap)
	}
	if spec.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	tmpfs := spec.TmpfsMounts
	if len(tmpfs) == 0 {
		tmpfs = []string{"/tmp:size=64m,nosuid,nodev,mode=1777", "/run:size=16m,nosuid,nodev,mode=1777"}
	}
	isZAP := spec.CaptureZAPReport || spec.Scanner == "zap" || spec.Scanner == "zap_baseline" || strings.Contains(spec.Invocation.Executable, "zap")
	if isZAP {
		hasHomeZap := false
		for _, m := range tmpfs {
			if strings.HasPrefix(m, "/home/zap") {
				hasHomeZap = true
			}
		}
		if !hasHomeZap {
			tmpfs = append(tmpfs, "/home/zap:size=256m,nosuid,nodev,mode=1777")
		}
		if spec.WorkspaceMount == "" {
			hasWrk := false
			for _, m := range tmpfs {
				if strings.HasPrefix(m, "/zap/wrk") {
					hasWrk = true
				}
			}
			if !hasWrk {
				tmpfs = append(tmpfs, "/zap/wrk:size=128m,nosuid,nodev,mode=1777")
			}
		}
	}
	for _, mount := range tmpfs {
		if spec.WorkspaceMount != "" && isZAP && strings.HasPrefix(mount, "/zap/wrk") {
			continue
		}
		normalized := mount
		if !strings.Contains(normalized, "noexec") {
			normalized += ",noexec"
		}
		if !strings.Contains(normalized, "nosuid") {
			normalized += ",nosuid"
		}
		if !strings.Contains(normalized, "nodev") {
			normalized += ",nodev"
		}
		if isZAP && !strings.Contains(normalized, "mode=") {
			normalized += ",mode=1777"
		}
		args = append(args, "--tmpfs="+normalized)
	}
	if spec.WorkspaceMount != "" {
		_ = os.Chmod(spec.WorkspaceMount, 0777)
		args = append(args, "-v", spec.WorkspaceMount+":/workspace:rw,z")
		if isZAP {
			args = append(args, "-v", spec.WorkspaceMount+":/zap/wrk:rw,z")
		}
	}
	if spec.Scanner == "nuclei" || strings.Contains(entrypoint, "nuclei") {
		templateHostPath := "/opt/kelvin/deploy/scanners/templates/kelvin.safe.web.v1"
		if _, err := os.Stat(templateHostPath); err == nil {
			args = append(args, "-v", templateHostPath+":/opt/kelvin/templates/kelvin.safe.web.v1:ro")
		}
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
	memHigh := ""
	if spec.Limits.MemoryHigh != "" {
		memHigh = spec.Limits.MemoryHigh
	} else if spec.MemoryHigh != "" {
		memHigh = spec.MemoryHigh
	}
	if memHigh != "" {
		args = append(args, "--memory-reservation="+memHigh)
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
	} else {
		networkName := os.Getenv("KELVIN_SCANNER_NETWORK")
		if networkName == "" {
			networkName = "kelvin-scanner-net"
		}
		args = append(args, "--network="+networkName)
	}
	for _, arg := range spec.Invocation.Args {
		targetHost := ""
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			if u, err := url.Parse(arg); err == nil && u.Hostname() != "" {
				targetHost = u.Hostname()
			}
		} else if !strings.HasPrefix(arg, "-") && strings.Contains(arg, ".") && net.ParseIP(arg) == nil {
			targetHost = arg
		}
		if targetHost != "" {
			if ips, err := net.LookupHost(targetHost); err == nil && len(ips) > 0 {
				args = append(args, "--add-host", targetHost+":"+ips[0])
			}
			break
		}
	}
	for _, opt := range spec.SecurityOpt {
		args = append(args, "--security-opt="+opt)
	}
	for _, env := range spec.Env {
		args = append(args, "--env", env)
	}
	if spec.Scanner == "nuclei" || strings.Contains(entrypoint, "nuclei") {
		args = append(args, "--env", "HOME=/tmp")
	}
	if spec.EgressProxy != "" && (spec.Scanner == "zap" || strings.Contains(spec.Invocation.Executable, "zap")) {
		if parsed, err := url.Parse(spec.EgressProxy); err == nil && parsed.Hostname() != "" {
			proxyHost := parsed.Hostname()
			proxyPort := parsed.Port()
			if proxyPort == "" {
				proxyPort = "80"
			}
			javaOpts := fmt.Sprintf("-Xmx1024m -Dhttp.proxyHost=%s -Dhttp.proxyPort=%s -Dhttps.proxyHost=%s -Dhttps.proxyPort=%s -Dhttp.nonProxyHosts=localhost|127.0.0.1", proxyHost, proxyPort, proxyHost, proxyPort)
			if parsed.User != nil {
				proxyUser := parsed.User.Username()
				proxyPass, _ := parsed.User.Password()
				javaOpts += fmt.Sprintf(" -Dhttp.proxyUser=%s -Dhttp.proxyPassword=%s -Dhttps.proxyUser=%s -Dhttps.proxyPassword=%s", proxyUser, proxyPass, proxyUser, proxyPass)
			}
			args = append(args, "--env", "JAVA_TOOL_OPTIONS="+javaOpts)
		}
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
			noProxyVal := "localhost,127.0.0.1"
			if spec.CaptureZAPReport || spec.Scanner == "zap" || spec.Scanner == "zap_baseline" || strings.Contains(spec.Invocation.Executable, "zap") {
				noProxyVal = "localhost,127.0.0.1,zap,::1"
			}
			args = append(args,
				"--env", "HTTP_PROXY="+spec.EgressProxy,
				"--env", "HTTPS_PROXY="+spec.EgressProxy,
				"--env", "http_proxy="+spec.EgressProxy,
				"--env", "https_proxy="+spec.EgressProxy,
				"--env", "ALL_PROXY="+spec.EgressProxy,
				"--env", "all_proxy="+spec.EgressProxy,
				"--env", "NO_PROXY="+noProxyVal,
				"--env", "no_proxy="+noProxyVal,
				"--env", "KELVIN_EGRESS_PROXY="+spec.EgressProxy,
			)
		}
	}
	workDir := spec.WorkingDir
	if spec.CaptureZAPReport || spec.Scanner == "zap" || strings.Contains(spec.Invocation.Executable, "zap") {
		workDir = "/zap/wrk"
	}
	if workDir != "" {
		args = append(args, "--workdir", workDir)
	}
	for key, value := range spec.Labels {
		args = append(args, "--label", key+"="+value)
	}
	imgRef := spec.Image
	if strings.Contains(imgRef, "@") {
		baseRef := strings.SplitN(imgRef, "@", 2)[0]
		cmd := exec.Command(e.RuntimePath(), "image", "exists", imgRef)
		cmd.Env = runtimeEnvironment()
		if err := cmd.Run(); err != nil {
			cmdBase := exec.Command(e.RuntimePath(), "image", "exists", baseRef)
			cmdBase.Env = runtimeEnvironment()
			if errBase := cmdBase.Run(); errBase == nil {
				imgRef = baseRef
			} else {
				cmdLatest := exec.Command(e.RuntimePath(), "image", "exists", baseRef+":latest")
				cmdLatest.Env = runtimeEnvironment()
				if errLatest := cmdLatest.Run(); errLatest == nil {
					imgRef = baseRef + ":latest"
				}
			}
		}
	}
	args = append(args, imgRef)
	invArgs := spec.Invocation.Args
	if spec.Scanner == "nuclei" || strings.Contains(spec.Invocation.Executable, "nuclei") {
		filtered := make([]string, 0, len(invArgs))
		skipNext := false
		for _, a := range invArgs {
			if skipNext {
				skipNext = false
				continue
			}
			if a == "-tags" || a == "-exclude-tags" {
				skipNext = true
				continue
			}
			filtered = append(filtered, a)
		}
		invArgs = filtered
	}
	if (spec.Scanner == "nmap" || spec.Invocation.Executable == "/usr/bin/nmap") && spec.EgressProxy != "" {
		hasProxies := false
		for _, a := range invArgs {
			if a == "--proxies" {
				hasProxies = true
				break
			}
		}
		if !hasProxies {
			invArgs = append([]string{"--proxies", spec.EgressProxy}, invArgs...)
		}
	}
	if spec.Scanner == "zap" || spec.Scanner == "zap_baseline" || strings.Contains(spec.Invocation.Executable, "zap-baseline.py") || strings.Contains(spec.Invocation.Executable, "zap-full-scan.py") {
		for i := 0; i < len(invArgs)-1; i++ {
			if invArgs[i] == "-J" {
				invArgs[i+1] = "kelvin-zap-report.json"
			}
		}
		hasSilent := false
		for i := 0; i < len(invArgs)-1; i++ {
			if invArgs[i] == "-z" {
				if !strings.Contains(invArgs[i+1], "-silent") {
					invArgs[i+1] = "-silent " + invArgs[i+1]
				}
				if !strings.Contains(invArgs[i+1], "checkforupdates.checkOnStart=false") {
					invArgs[i+1] = invArgs[i+1] + " -config checkforupdates.checkOnStart=false -config telemetry.optin=false"
				}
				hasSilent = true
				break
			}
		}
		if !hasSilent {
			invArgs = append(invArgs, "-z", "-silent -config checkforupdates.checkOnStart=false -config telemetry.optin=false")
		}
		if spec.EgressProxy != "" {
			if parsed, err := url.Parse(spec.EgressProxy); err == nil && parsed.Hostname() != "" {
				proxyHost := parsed.Hostname()
				proxyPort := parsed.Port()
				if proxyPort == "" {
					proxyPort = "80"
				}
				proxyOpts := fmt.Sprintf("-config connection.proxyChain.enabled=true -config connection.proxyChain.hostName=%s -config connection.proxyChain.port=%s -config network.connection.httpProxy.enabled=true -config network.connection.httpProxy.hostName=%s -config network.connection.httpProxy.port=%s", proxyHost, proxyPort, proxyHost, proxyPort)
				if parsed.User != nil {
					proxyUser := parsed.User.Username()
					proxyPass, _ := parsed.User.Password()
					proxyOpts += fmt.Sprintf(" -config connection.proxyChain.authEnabled=true -config connection.proxyChain.userName=%s -config connection.proxyChain.password=%s -config network.connection.httpProxy.authEnabled=true -config network.connection.httpProxy.userName=%s -config network.connection.httpProxy.password=%s", proxyUser, proxyPass, proxyUser, proxyPass)
				}
				hasZ := false
				for i := 0; i < len(invArgs)-1; i++ {
					if invArgs[i] == "-z" {
						invArgs[i+1] = invArgs[i+1] + " " + proxyOpts
						hasZ = true
						break
					}
				}
				if !hasZ {
					invArgs = append(invArgs, "-z", proxyOpts)
				}
			}
		}
	}
	args = append(args, invArgs...)
	return args
}

func (e *OCIExecutor) captureZAPReport(containerName string, result *Result, spec Spec) error {
	if spec.WorkspaceMount != "" {
		hostCandidates := []string{
			filepath.Join(spec.WorkspaceMount, "kelvin-zap-report.json"),
			filepath.Join(spec.WorkspaceMount, "report.json"),
			filepath.Join(spec.WorkspaceMount, "zap.json"),
		}
		for _, hostFile := range hostCandidates {
			if content, err := os.ReadFile(hostFile); err == nil && len(content) > 0 {
				if len(content) > maxCaptureBytes {
					return fmt.Errorf("report exceeds %d bytes", maxCaptureBytes)
				}
				result.Findings = content
				return nil
			}
		}
	}

	dir, err := os.MkdirTemp("", "kelvin-zap-report-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	destination := filepath.Join(dir, "report.json")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	candidates := []string{
		containerName + ":/tmp/kelvin-zap-report.json",
		containerName + ":/zap/wrk/kelvin-zap-report.json",
		containerName + ":/zap/wrk/report.json",
		containerName + ":/home/zap/zap_out.json",
	}

	var copyErr error
	copied := false
	for _, src := range candidates {
		args := []string{"cp", src, destination}
		cmd := exec.CommandContext(ctx, e.runtime, args...)
		cmd.Env = runtimeEnvironment()
		if err := cmd.Run(); err == nil {
			if fi, err := os.Stat(destination); err == nil && fi.Size() > 0 {
				copied = true
				break
			}
		} else {
			copyErr = err
		}
	}
	if !copied {
		return fmt.Errorf("OCI runtime report copy failed: %w", copyErr)
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


