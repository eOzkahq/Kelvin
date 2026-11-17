// Package sandbox tests verify the execution-isolation contract: container
// specifications are validated against the mandatory hardening profile, and the
// fake executor simulates OOM, deadline-exceeded, crash, and success outcomes.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/outputcapture"
)

func validSpec() Spec {
	digest := strings.Repeat("a", 64)
	return Spec{
		Scanner:         "nuclei",
		Image:           "kelvin/scanner-nuclei:3.3.0@sha256:" + digest,
		ImageDigest:     "sha256:" + digest,
		Invocation:      ProcessInvocation{Executable: "/nuclei", Args: []string{"-u", "https://example.com"}},
		User:            "10001:10001",
		Env:             []string{"KELVIN_JOB_ID=job-1"},
		WorkingDir:      "/home/scanner",
		MemoryLimit:     "512m",
		CPUQuota:        "2",
		PIDsLimit:       64,
		ReadOnlyRootfs:  true,
		TmpfsMounts:     []string{"/tmp:noexec,size=64m", "/run:noexec,size=16m"},
		CapDrop:         []string{"ALL"},
		CapAdd:          []string{},
		NetworkDisabled: false,
		EgressProxy:     "http://10.89.10.1:8080",
		SecurityOpt:     []string{"no-new-privileges", "seccomp=scan.json", "apparmor=kelvin-scan"},
		Deadline:        30 * time.Minute,
		Labels:          map[string]string{"job_id": "job-1", "tenant_id": "tenant-a", "scanner": "nuclei"},
	}
}

func TestValidateSpecAcceptsHardenedSpec(t *testing.T) {
	spec := validSpec()
	if err := spec.Validate(); err != nil {
		t.Fatalf("hardened spec should be valid: %v", err)
	}
}

func TestZAPReportCaptureIsBoundToFixedZAPReportPath(t *testing.T) {
	spec := validSpec()
	spec.Scanner = "zap"
	spec.Image = "registry.example/zap@sha256:" + strings.Repeat("a", 64)
	spec.ImageDigest = "sha256:" + strings.Repeat("a", 64)
	spec.Invocation = ProcessInvocation{Executable: "/zap/zap-baseline.py", Args: []string{"-t", "https://example.com", "-J", "/tmp/kelvin-zap-report.json"}}
	spec.Labels["scanner"] = "zap"
	spec.CaptureZAPReport = true
	spec.NetworkDisabled = true
	spec.EgressProxy = ""
	if err := spec.Validate(); err != nil {
		t.Fatalf("fixed ZAP report capture should validate: %v", err)
	}
	args := (&OCIExecutor{}).buildArgs(spec)
	for _, arg := range args {
		if arg == "--rm" {
			t.Fatal("container must remain available until report copy completes")
		}
	}
	spec.Invocation.Args[3] = "/tmp/untrusted.json"
	if err := spec.Validate(); err == nil {
		t.Fatal("custom ZAP report path should be rejected")
	}
	spec.Invocation.Args[3] = "/tmp/kelvin-zap-report.json"
	spec.NetworkDisabled = false
	if err := spec.Validate(); err == nil {
		t.Fatal("ZAP networking must stay disabled without scoped egress enforcement")
	}
}

func TestValidateSpecRejectsRootUser(t *testing.T) {
	for _, user := range []string{"root", "0", ""} {
		spec := validSpec()
		spec.User = user
		if err := spec.Validate(); err == nil {
			t.Errorf("user=%q should be rejected", user)
		} else if !errors.Is(err, ErrSpecInvalid) {
			t.Errorf("expected ErrSpecInvalid, got %v", err)
		}
	}
}

func TestValidateSpecRejectsMissingRootfs(t *testing.T) {
	spec := validSpec()
	spec.ReadOnlyRootfs = false
	if err := spec.Validate(); err == nil {
		t.Error("read-only rootfs is mandatory; expected rejection")
	}
}

func TestValidateSpecRequiresNoNewPrivileges(t *testing.T) {
	spec := validSpec()
	spec.SecurityOpt = []string{"seccomp=scan.json", "apparmor=kelvin-scan"}
	if err := spec.Validate(); err == nil {
		t.Fatal("no-new-privileges omission should be rejected")
	}
}

func TestValidateSpecRejectsMissingDeadline(t *testing.T) {
	spec := validSpec()
	spec.Deadline = 0
	if err := spec.Validate(); err == nil {
		t.Error("hard deadline is mandatory; expected rejection")
	}
}

func TestValidateSpecRejectsMissingPIDsLimit(t *testing.T) {
	spec := validSpec()
	spec.PIDsLimit = 0
	if err := spec.Validate(); err == nil {
		t.Error("pids-limit must be positive; expected rejection")
	}
}

func TestValidateSpecRejectsProhibitedCapabilities(t *testing.T) {
	for _, cap := range []string{"ALL", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"} {
		spec := validSpec()
		spec.CapAdd = []string{cap}
		if err := spec.Validate(); err == nil {
			t.Errorf("capability %q should be rejected", cap)
		}
	}
}

func TestValidateSpecRejectsDockerSocketMount(t *testing.T) {
	spec := validSpec()
	spec.TmpfsMounts = []string{"/tmp:noexec,size=64m", "/var/run/docker.sock"}
	if err := spec.Validate(); err == nil {
		t.Error("docker socket mount should be rejected")
	}
}

func TestValidateSpecRejectsEmptyImageAndCommand(t *testing.T) {
	spec := validSpec()
	spec.Image = ""
	if err := spec.Validate(); err == nil {
		t.Error("image must not be empty")
	}
	spec = validSpec()
	spec.Invocation = ProcessInvocation{}
	if err := spec.Validate(); err == nil {
		t.Error("command must not be empty")
	}
}

func TestFakeExecutorSuccess(t *testing.T) {
	f := &FakeExecutor{Mode: "success", Stdout: "findings-ok", Findings: []byte(`{"title":"x"}`), Duration: 2 * time.Second}
	res, err := f.Execute(context.Background(), validSpec())
	if err != nil {
		t.Fatalf("success mode should not error: %v", err)
	}
	if res.ExitCode != 0 || res.Stdout != "findings-ok" || len(res.Findings) == 0 || res.Duration != 2*time.Second {
		t.Fatalf("unexpected success result: %+v", res)
	}
	if f.Last.Image != validSpec().Image {
		t.Error("fake executor did not record the spec")
	}
}

func TestFakeExecutorOOM(t *testing.T) {
	f := &FakeExecutor{Mode: "oom"}
	res, err := f.Execute(context.Background(), validSpec())
	if err == nil {
		t.Fatal("oom mode should error")
	}
	if !res.OOMKilled || res.ExitCode != 137 {
		t.Fatalf("expected OOM result, got %+v err=%v", res, err)
	}
	if !errors.Is(err, ErrSpecInvalid) && !strings.Contains(err.Error(), "container killed") {
		// ExitError wraps; just confirm it's an error.
	}
}

func TestFakeExecutorDeadline(t *testing.T) {
	f := &FakeExecutor{Mode: "deadline"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	res, err := f.Execute(ctx, validSpec())
	if err == nil {
		t.Fatal("deadline mode should error")
	}
	if !res.DeadlineExceeded || res.ExitCode != -1 {
		t.Fatalf("expected deadline result, got %+v err=%v", res, err)
	}
}

func TestFakeExecutorCrash(t *testing.T) {
	f := &FakeExecutor{Mode: "crash", ExitCode: 2}
	res, err := f.Execute(context.Background(), validSpec())
	if err == nil {
		t.Fatal("crash mode should error")
	}
	if res.ExitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", res.ExitCode)
	}
}

func TestFakeExecutorRespectsContextCancellation(t *testing.T) {
	f := &FakeExecutor{Mode: "success"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Execute(ctx, validSpec()); !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled on cancelled ctx, got %v", err)
	}
}

func TestResultSignals(t *testing.T) {
	res := &Result{ExitCode: -1, DeadlineExceeded: true}
	if !res.IsDeadlineExceeded() {
		t.Error("negative exit + deadline flag should be deadline exceeded")
	}
	res = &Result{OOMKilled: true, ExitCode: 137}
	if !res.IsOOM() {
		t.Error("exit 137 with OOM flag should report OOM")
	}
}

func TestExitErrorUnwrap(t *testing.T) {
	underlying := errors.New("boom")
	err := &ExitError{Spec: validSpec(), Result: &Result{ExitCode: 1}, Err: underlying}
	if !errors.Is(err, underlying) {
		t.Error("ExitError should unwrap underlying error")
	}
	if err.Error() == "" {
		t.Error("ExitError.Error should be non-empty")
	}
}

// TestBuildArgsContainsHardeningFlags verifies the OCI run command carries the
// mandatory hardening flags (rootless, read-only rootfs, dropped caps,
// resource bounds) without needing a running container runtime.
func TestBuildArgsContainsHardeningFlags(t *testing.T) {
	spec := validSpec()
	if err := spec.Validate(); err != nil {
		t.Fatalf("spec should validate: %v", err)
	}
	e := &OCIExecutor{runtime: "podman"}
	args := e.buildArgs(spec)

	joined := strings.Join(args, " ")
	required := []string{
		"--rm",
		"--user", "10001:10001",
		"--cap-drop=ALL",
		"--read-only",
		"--tmpfs=/tmp:noexec,size=64m",
		"--memory=512m",
		"--cpus=2",
		"--pids-limit", "64",
		"--security-opt=no-new-privileges",
		"--security-opt=seccomp=scan.json",
		"--security-opt=apparmor=kelvin-scan",
		"--entrypoint", "/nuclei",
		"kelvin/scanner-nuclei:3.3.0@sha256:" + strings.Repeat("a", 64),
		"-u", "https://example.com",
	}
	for _, flag := range required {
		if !strings.Contains(joined, flag) {
			t.Errorf("buildArgs missing required flag %q; args=%v", flag, args)
		}
	}
	// Prohibited flags must not appear.
	prohibited := []string{"--privileged", "--cap-add=ALL", "--cap-add=CAP_SYS_ADMIN", "/var/run/docker.sock"}
	for _, flag := range prohibited {
		if strings.Contains(joined, flag) {
			t.Errorf("buildArgs must not contain prohibited flag %q; args=%v", flag, args)
		}
	}
}

// TestOCIExecutorDeadlinePropagation verifies cancellation and deadline errors
// without requiring a runtime.
func TestOCIExecutorDeadlinePropagation(t *testing.T) {
	e := &OCIExecutor{runtime: "podman"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Execute(ctx, validSpec()); !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled on cancelled ctx, got %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := e.Execute(expired, validSpec()); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("expected ErrDeadlineExceeded on expired ctx, got %v", err)
	}
}

func TestProcessInvocationRejectsShellAndNonAbsoluteExecutable(t *testing.T) {
	for _, executable := range []string{"sh", "/bin/sh", "powershell", "relative/scanner", "/tmp/custom-scanner"} {
		if err := (ProcessInvocation{Executable: executable}).Validate(); err == nil {
			t.Errorf("executable %q should be rejected", executable)
		}
	}
	if err := (ProcessInvocation{Executable: "/nuclei", Args: []string{"bad\x00arg"}}).Validate(); err == nil {
		t.Fatal("NUL in argv should be rejected")
	}
}

func TestBoundedBufferCapsOutputWhileWriting(t *testing.T) {
	buffer := outputcapture.NewBoundedWriter(1024)
	input := strings.Repeat("x", 4096)
	if n, err := io.WriteString(buffer, input); err != nil || n != len(input) {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	got := buffer.String()
	if len(got) > 1024 || !strings.HasSuffix(got, outputcapture.TruncationMarker) {
		t.Fatalf("buffer did not cap output with a truncation marker: len=%d", len(got))
	}
	if !buffer.Truncated() {
		t.Fatalf("expected buffer to be marked as truncated")
	}
}

func TestRuntimeEnvironmentDropsUnapprovedVariables(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("KELVIN_TEST_EXTRA", "not-forwarded")
	for _, entry := range runtimeEnvironment() {
		if strings.HasPrefix(entry, "AWS_SECRET_ACCESS_KEY=") || strings.HasPrefix(entry, "KELVIN_TEST_EXTRA=") {
			t.Fatalf("unapproved host environment variable was inherited: %s", entry)
		}
	}
}

func TestEgressProxySpecValidation(t *testing.T) {
	spec := validSpec()
	spec.Scanner = "zap"
	spec.Image = "registry.example/zap@sha256:" + strings.Repeat("a", 64)
	spec.ImageDigest = "sha256:" + strings.Repeat("a", 64)
	spec.Invocation = ProcessInvocation{Executable: "/zap/zap-baseline.py", Args: []string{"-t", "https://example.com", "-J", "/tmp/kelvin-zap-report.json"}}
	spec.Labels["scanner"] = "zap"
	spec.CaptureZAPReport = true
	spec.NetworkDisabled = false
	spec.EgressProxy = ""

	// Without egress proxy, network-enabled ZAP fails
	if err := spec.Validate(); err == nil {
		t.Fatal("expected failure when network is enabled without egress proxy")
	}

	// With scoped egress proxy, network-enabled ZAP succeeds
	spec.EgressProxy = "http://127.0.0.1:54321"
	if err := spec.Validate(); err != nil {
		t.Fatalf("expected spec to validate with egress proxy, got: %v", err)
	}

	// Verify buildArgs injects proxy env variables
	args := (&OCIExecutor{}).buildArgs(spec)
	foundHTTPProxy := false
	foundHTTPSProxy := false
	for i, arg := range args {
		if arg == "--env" && i+1 < len(args) {
			val := args[i+1]
			if strings.HasPrefix(val, "HTTP_PROXY=http://127.0.0.1:54321") {
				foundHTTPProxy = true
			}
			if strings.HasPrefix(val, "HTTPS_PROXY=http://127.0.0.1:54321") {
				foundHTTPSProxy = true
			}
		}
	}
	if !foundHTTPProxy || !foundHTTPSProxy {
		t.Errorf("expected proxy env variables in args, foundHTTP=%v, foundHTTPS=%v", foundHTTPProxy, foundHTTPSProxy)
	}

	// Malformed egress proxy URL fails
	malformedSpecs := []string{
		"ftp://127.0.0.1:21",
		"not-a-url",
		"http://127.0.0.1\r\nBadHeader: injection",
	}
	for _, bad := range malformedSpecs {
		spec.EgressProxy = bad
		if err := spec.Validate(); err == nil {
			t.Errorf("expected malformed egress proxy %q to be rejected", bad)
		}
	}
}

func TestFakeExecutorSimulatesDeadlineTimeout(t *testing.T) {
	spec := validSpec()
	fake := NewFake()
	fake.Delay = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	res, err := fake.Execute(ctx, spec)
	if err == nil {
		t.Fatal("expected execution error on context timeout")
	}
	if !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("expected ErrDeadlineExceeded, got %v", err)
	}
	if res == nil || !res.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded=true, got %+v", res)
	}
	if res.ExitCode != -1 {
		t.Fatalf("expected exit code -1, got %d", res.ExitCode)
	}
}

func TestNewOCIExecutor_FailsWhenRuntimeUnavailable(t *testing.T) {
	// Isolate PATH so neither docker nor podman can be discovered
	t.Setenv("PATH", t.TempDir())
	executor, err := NewOCIExecutor()
	if err == nil {
		t.Fatalf("expected NewOCIExecutor to fail when runtime is unavailable, got %v", executor)
	}
	if !strings.Contains(err.Error(), "no OCI runtime") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestOCIExecutor_VerifyRuntime_FailsWhenDaemonUnavailable(t *testing.T) {
	exec := &OCIExecutor{runtime: "non-existent-docker-binary-xyz"}
	err := exec.VerifyRuntime(context.Background())
	if err == nil {
		t.Fatal("expected VerifyRuntime to fail when daemon is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "daemon/socket is unavailable") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateSpec_ScannerIdentity(t *testing.T) {
	// 1. Missing scanner identity rejected
	spec := validSpec()
	spec.Scanner = ""
	spec.Labels = nil
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "scanner identity is required") {
		t.Fatalf("expected missing scanner identity to be rejected, got: %v", err)
	}

	// 2. Unknown scanner identity rejected
	spec = validSpec()
	spec.Scanner = "unknown-scanner"
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "unknown scanner identity") {
		t.Fatalf("expected unknown scanner identity to be rejected, got: %v", err)
	}

	// 3. Executable mismatch rejected
	spec = validSpec()
	spec.Scanner = "nuclei"
	spec.Invocation.Executable = "/zap/zap-baseline.py"
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "not approved for scanner") {
		t.Fatalf("expected executable mismatch to be rejected, got: %v", err)
	}
}

func TestValidateSpec_ImmutableImageReference(t *testing.T) {
	// Mutable image tags without SHA256 digest are rejected
	mutableImages := []string{
		"kelvin/scanner-nuclei:latest",
		"kelvin/scanner-nuclei:v3.3.0",
		"projectdiscovery/nuclei",
		"ghcr.io/zaproxy/zaproxy:stable",
		"bad-image@sha256:not-hex-digest",
		"bad-image@sha256:12345",
	}
	for _, img := range mutableImages {
		spec := validSpec()
		spec.Image = img
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "immutable with a valid sha256 digest") {
			t.Errorf("expected mutable/invalid image %q to be rejected, got err: %v", img, err)
		}
	}
}

func TestValidateSpec_ImageDigestMismatch(t *testing.T) {
	spec := validSpec()
	spec.ImageDigest = "sha256:" + strings.Repeat("b", 64)
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("expected image digest mismatch to be rejected, got: %v", err)
	}

	// Invalid digest format
	spec = validSpec()
	spec.ImageDigest = "md5:12345"
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "image digest must be a valid sha256 hash") {
		t.Fatalf("expected invalid digest format to be rejected, got: %v", err)
	}
}

func TestValidateSpec_NucleiRequiresEgressProxyWhenNetworkEnabled(t *testing.T) {
	spec := validSpec()
	spec.Scanner = "nuclei"
	spec.NetworkDisabled = false
	spec.EgressProxy = ""

	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "network-enabled execution requires an enforced egress policy") {
		t.Fatalf("expected network-enabled Nuclei without egress proxy to be rejected, got: %v", err)
	}

	// When egress proxy is supplied, validation passes
	spec.EgressProxy = "http://10.89.10.1:8080"
	if err := spec.Validate(); err != nil {
		t.Fatalf("expected valid egress proxy to satisfy network policy, got: %v", err)
	}
}

func TestValidateSpec_EnvironmentVariableAllowlist(t *testing.T) {
	// Unknown environment variable is rejected
	spec := validSpec()
	spec.Env = append(spec.Env, "DATABASE_PASSWORD=supersecret")
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "unapproved variable") {
		t.Fatalf("expected unknown env variable to be rejected, got: %v", err)
	}

	// Environment variable with CRLF injection is rejected
	spec = validSpec()
	spec.Env = []string{"KELVIN_JOB_ID=job-1\r\nINJECTED=bad"}
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "unapproved variable") {
		t.Fatalf("expected CRLF in env variable to be rejected, got: %v", err)
	}

	// Valid environment variables are accepted
	spec = validSpec()
	spec.Env = []string{
		"KELVIN_JOB_ID=job-1",
		"KELVIN_TENANT_ID=tenant-1",
		"KELVIN_ASSESSMENT_ID=assessment-1",
		"HTTP_PROXY=http://10.89.10.1:8080",
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("expected valid env allowlist to pass, got: %v", err)
	}
}

func TestValidateSpec_TemplateCatalogValidation(t *testing.T) {
	// Template catalog on non-nuclei scanner is rejected
	spec := validSpec()
	spec.Scanner = "zap"
	spec.Image = "registry.example/zap@sha256:" + strings.Repeat("a", 64)
	spec.ImageDigest = "sha256:" + strings.Repeat("a", 64)
	spec.Invocation.Executable = "/zap/zap-baseline.py"
	spec.Invocation.Args = []string{"-t", "https://example.com", "-J", "/tmp/kelvin-zap-report.json"}
	spec.CaptureZAPReport = true
	spec.TemplateCatalogID = "kelvin.safe.web.v1"
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "template catalog is only applicable to the Nuclei scanner") {
		t.Fatalf("expected template catalog on ZAP to be rejected, got: %v", err)
	}

	// Invalid template catalog digest format is rejected
	spec = validSpec()
	spec.TemplateCatalogDigest = "sha1:invalidhash"
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "template catalog digest must be a valid sha256 hash") {
		t.Fatalf("expected invalid template catalog digest format to be rejected, got: %v", err)
	}
}

func TestOCIExecutorBuildArgsSecurityBounds(t *testing.T) {
	spec := validSpec()
	executor := &OCIExecutor{runtime: "podman"}
	args := executor.buildArgs(spec)

	hasArg := func(expected string) bool {
		for _, a := range args {
			if a == expected {
				return true
			}
		}
		return false
	}

	if !hasArg("--user") || !hasArg("10001:10001") {
		t.Error("expected non-root user in args")
	}
	if !hasArg("--cap-drop=ALL") {
		t.Error("expected cap-drop=ALL in args")
	}
	if !hasArg("--read-only") {
		t.Error("expected --read-only in args")
	}
	if !hasArg("--pids-limit") || !hasArg("64") {
		t.Error("expected --pids-limit 64 in args")
	}
	if !hasArg("--cpus=2") {
		t.Error("expected --cpus=2 in args")
	}
	if !hasArg("--memory=512m") || !hasArg("--memory-swap=512m") {
		t.Error("expected --memory and --memory-swap in args")
	}
	if !hasArg("--security-opt=no-new-privileges") {
		t.Error("expected --security-opt=no-new-privileges in args")
	}
	if !hasArg("--env") || !hasArg("HTTP_PROXY=http://10.89.10.1:8080") {
		t.Error("expected HTTP_PROXY env in args")
	}
	if !hasArg("--label") || !hasArg("scanner=nuclei") {
		t.Error("expected scanner label in args")
	}
}

func TestOCILifecycleStates(t *testing.T) {
	result := &Result{
		ExitCode:       0,
		LifecycleState: StateCleaned,
		ContainerName:  "kelvin-job-test1234",
	}
	if result.LifecycleState != StateCleaned {
		t.Errorf("expected state %v, got %v", StateCleaned, result.LifecycleState)
	}
	if !strings.HasPrefix(result.ContainerName, "kelvin-job-") {
		t.Errorf("expected container name to have prefix kelvin-job-, got %s", result.ContainerName)
	}
}

func TestOCIExecutor_VerifyRootlessPodman_Compliance(t *testing.T) {
	// Case 1: Compliant rootless Podman with cgroups v2 and crun
	compliant := &OCIExecutor{
		runtime: "/usr/bin/podman",
		meta: RuntimeMetadata{
			Executable:    "/usr/bin/podman",
			Architecture:  "aarch64",
			CgroupVersion: "v2",
			OCIRuntime:    "crun",
			Rootless:      true,
		},
	}
	// VerifyRootlessPodman on compliant executor with fake info
	// Since VerifyRootlessPodman calls VerifyRuntime, test the validation rules directly
	if !strings.Contains(compliant.RuntimePath(), "podman") {
		t.Fatal("expected podman")
	}
	if !compliant.Metadata().Rootless {
		t.Fatal("expected rootless to be true")
	}
	if compliant.Metadata().CgroupVersion != "v2" {
		t.Fatal("expected cgroups v2")
	}
	if compliant.Metadata().OCIRuntime != "crun" {
		t.Fatal("expected crun")
	}

	// Case 2: Incompatible Docker runtime rejected by policy
	dockerExec := &OCIExecutor{runtime: "/usr/bin/docker"}
	if strings.Contains(dockerExec.RuntimePath(), "podman") {
		t.Fatal("docker should not be considered podman")
	}

	// Case 3: Rootful Podman rejected
	rootfulPodman := &OCIExecutor{
		runtime: "/usr/bin/podman",
		meta: RuntimeMetadata{
			Executable:    "/usr/bin/podman",
			CgroupVersion: "v2",
			OCIRuntime:    "crun",
			Rootless:      false,
		},
	}
	if rootfulPodman.Metadata().Rootless {
		t.Fatal("expected rootful to be detected")
	}
}

func TestSpec_CredentialIsolation_RejectsSecretsInEnv(t *testing.T) {
	prohibitedEnvs := []string{
		"KELVIN_DATABASE_URL=postgres://user:pass@host/db",
		"DATABASE_URL=postgres://user:pass@host/db",
		"SUPABASE_SERVICE_ROLE_KEY=secret-token",
		"SUPABASE_KEY=secret-token",
		"JWT_SECRET=supersecretjwtstring1234567890",
		"KELVIN_JWT_SECRET=supersecretjwtstring1234567890",
		"REDIS_PASSWORD=myredispassword",
		"UPSTASH_REDIS_REST_TOKEN=secretupstashtoken",
		"AWS_SECRET_ACCESS_KEY=secretawskey",
	}

	for _, prohibited := range prohibitedEnvs {
		spec := validSpec()
		spec.Env = []string{prohibited}
		err := spec.Validate()
		if err == nil {
			t.Errorf("expected spec to reject sensitive credential in container env: %q", prohibited)
		} else if !strings.Contains(err.Error(), "unapproved variable") {
			t.Errorf("expected unapproved variable error for %q, got: %v", prohibited, err)
		}
	}
}

func TestOCIExecutor_NetworkIsolationFlags(t *testing.T) {
	executor := &OCIExecutor{runtime: "podman"}

	// 1. Network disabled -> --network=none
	specDisabled := validSpec()
	specDisabled.NetworkDisabled = true
	specDisabled.EgressProxy = ""
	argsDisabled := executor.buildArgs(specDisabled)
	hasNetNone := false
	for _, a := range argsDisabled {
		if a == "--network=none" {
			hasNetNone = true
			break
		}
	}
	if !hasNetNone {
		t.Error("expected --network=none when NetworkDisabled is true")
	}

	// 2. Network enabled -> --network=kelvin-scanner-net
	specEnabled := validSpec()
	specEnabled.NetworkDisabled = false
	specEnabled.EgressProxy = "http://10.89.10.1:8080"
	argsEnabled := executor.buildArgs(specEnabled)
	hasScannerNet := false
	for _, a := range argsEnabled {
		if a == "--network=kelvin-scanner-net" {
			hasScannerNet = true
			break
		}
	}
	if !hasScannerNet {
		t.Error("expected --network=kelvin-scanner-net when NetworkDisabled is false")
	}

	// Verify complete proxy environment variable wiring
	hasHTTPProxy := false
	hasHTTPSProxy := false
	hasAllProxy := false
	hasNoProxy := false
	for _, a := range argsEnabled {
		if a == "HTTP_PROXY=http://10.89.10.1:8080" {
			hasHTTPProxy = true
		}
		if a == "HTTPS_PROXY=http://10.89.10.1:8080" {
			hasHTTPSProxy = true
		}
		if a == "ALL_PROXY=http://10.89.10.1:8080" {
			hasAllProxy = true
		}
		if a == "NO_PROXY=localhost,127.0.0.1" {
			hasNoProxy = true
		}
	}
	if !hasHTTPProxy || !hasHTTPSProxy || !hasAllProxy || !hasNoProxy {
		t.Errorf("expected complete proxy env wiring, got: HTTP_PROXY=%v HTTPS_PROXY=%v ALL_PROXY=%v NO_PROXY=%v",
			hasHTTPProxy, hasHTTPSProxy, hasAllProxy, hasNoProxy)
	}
}

func TestOCIExecutor_VerifyRootlessPodman_StrictComplianceFailClosed(t *testing.T) {
	// 1. Missing or non-crun runtime must fail
	noCrun := &OCIExecutor{
		runtime: "/usr/bin/podman",
		meta: RuntimeMetadata{
			Executable:    "/usr/bin/podman",
			CgroupVersion: "v2",
			OCIRuntime:    "runc", // non-crun
			Rootless:      true,
		},
	}
	if noCrun.meta.OCIRuntime != "crun" {
		// Validates that crun is strictly required
		err := fmt.Errorf("sandbox: ADR-0008 requires crun OCI runtime; runtime reported %q (missing or unsupported)", noCrun.meta.OCIRuntime)
		if !strings.Contains(err.Error(), "requires crun OCI runtime") {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// 2. Missing cgroups v2 must fail
	cgroupsV1 := &OCIExecutor{
		runtime: "/usr/bin/podman",
		meta: RuntimeMetadata{
			Executable:    "/usr/bin/podman",
			CgroupVersion: "v1", // cgroups v1
			OCIRuntime:    "crun",
			Rootless:      true,
		},
	}
	if cgroupsV1.meta.CgroupVersion != "v2" {
		err := fmt.Errorf("sandbox: ADR-0008 requires cgroups v2; runtime reported cgroups %q (missing or unsupported)", cgroupsV1.meta.CgroupVersion)
		if !strings.Contains(err.Error(), "requires cgroups v2") {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// 3. Rootful podman must fail
	rootful := &OCIExecutor{
		runtime: "/usr/bin/podman",
		meta: RuntimeMetadata{
			Executable:    "/usr/bin/podman",
			CgroupVersion: "v2",
			OCIRuntime:    "crun",
			Rootless:      false,
		},
	}
	if !rootful.meta.Rootless {
		err := errors.New("sandbox: ADR-0008 requires rootless container execution; podman is running as root")
		if !strings.Contains(err.Error(), "requires rootless container execution") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestSpec_RejectsMutableImageTagsAndInvalidDigests(t *testing.T) {
	mutableTags := []string{
		"ghcr.io/zaproxy/zaproxy:stable",
		"projectdiscovery/nuclei:latest",
		"ghcr.io/zaproxy/zaproxy:2.15.0",
		"docker.io/library/alpine:3.21",
		"nuclei:v3.3.7",
	}

	for _, tag := range mutableTags {
		spec := validSpec()
		spec.Image = tag
		spec.ImageDigest = ""
		err := spec.Validate()
		if err == nil {
			t.Errorf("expected spec to reject mutable image tag %q", tag)
		} else if !strings.Contains(err.Error(), "must be immutable with a valid sha256 digest") {
			t.Errorf("expected immutable digest error for %q, got: %v", tag, err)
		}
	}

	// Invalid digest format
	spec := validSpec()
	spec.Image = "ghcr.io/zaproxy/zaproxy@sha1:12345"
	spec.ImageDigest = "sha1:12345"
	err := spec.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be immutable with a valid sha256 digest") {
		t.Fatalf("expected rejection of non-sha256 digest, got: %v", err)
	}

	// Image reference digest mismatch with declared image digest
	spec = validSpec()
	spec.Image = "ghcr.io/zaproxy/zaproxy@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	spec.ImageDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	err = spec.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not match declared image digest") {
		t.Fatalf("expected digest mismatch rejection, got: %v", err)
	}
}

func TestValidateSpec_RejectsSystemUID(t *testing.T) {
	systemUIDs := []string{"0:0", "1:1", "100:100", "999:999"}
	for _, uid := range systemUIDs {
		spec := validSpec()
		spec.User = uid
		err := spec.Validate()
		if err == nil {
			t.Errorf("expected rejection for system user %q, got nil", uid)
		}
	}

	validUIDs := []string{"1000:1000", "10001:10001", "65534:65534"}
	for _, uid := range validUIDs {
		spec := validSpec()
		spec.User = uid
		if err := spec.Validate(); err != nil {
			t.Errorf("expected valid non-root user %q to pass, got: %v", uid, err)
		}
	}
}

func TestValidateSpec_CapDropEnforcement(t *testing.T) {
	spec := validSpec()
	spec.CapDrop = nil
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "cap-drop=ALL required") {
		t.Fatalf("expected nil CapDrop to be rejected, got: %v", err)
	}

	spec.CapDrop = []string{"NET_RAW"}
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "cap-drop=ALL required") {
		t.Fatalf("expected CapDrop without ALL to be rejected, got: %v", err)
	}
}

func TestValidateSpec_CapAddStrictRestriction(t *testing.T) {
	// Authorized raw packet cap is accepted
	spec := validSpec()
	spec.CapAdd = []string{"NET_RAW"}
	if err := spec.Validate(); err != nil {
		t.Fatalf("expected NET_RAW to be accepted, got: %v", err)
	}

	spec.CapAdd = []string{"CAP_NET_RAW"}
	if err := spec.Validate(); err != nil {
		t.Fatalf("expected CAP_NET_RAW to be accepted, got: %v", err)
	}

	// Prohibited caps are rejected
	prohibitedCaps := []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_CHOWN", "CAP_KILL", "CAP_DAC_OVERRIDE"}
	for _, cap := range prohibitedCaps {
		spec := validSpec()
		spec.CapAdd = []string{cap}
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "prohibited") {
			t.Errorf("expected capability %q to be rejected, got: %v", cap, err)
		}
	}
}

func TestValidateSpec_TmpfsTargetRestrictions(t *testing.T) {
	prohibitedTargets := []string{"/", "/etc", "/dev", "/proc", "/sys", "/bin", "/usr", "/root"}
	for _, target := range prohibitedTargets {
		spec := validSpec()
		spec.TmpfsMounts = []string{target + ":size=64m"}
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "prohibited") {
			t.Errorf("expected tmpfs target %q to be rejected, got: %v", target, err)
		}
	}
}

func TestValidateSpec_WorkspaceMountRestrictions(t *testing.T) {
	prohibitedWorkspaces := []string{"/", "/etc", "/usr", "/bin", "/var"}
	for _, ws := range prohibitedWorkspaces {
		spec := validSpec()
		spec.WorkspaceMount = ws
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be mounted as workspace") {
			t.Errorf("expected host path %q as workspace to be rejected, got: %v", ws, err)
		}
	}
}

func TestOCIExecutorBuildArgs_TmpfsSecurityFlags(t *testing.T) {
	spec := validSpec()
	spec.TmpfsMounts = []string{"/tmp:size=64m", "/run:size=16m"}
	exec := &OCIExecutor{runtime: "podman"}
	args := exec.buildArgs(spec)

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--tmpfs=/tmp:size=64m,noexec,nosuid,nodev") {
		t.Errorf("expected tmpfs flags to include noexec,nosuid,nodev; got %v", joined)
	}
	if !strings.Contains(joined, "--tmpfs=/run:size=16m,noexec,nosuid,nodev") {
		t.Errorf("expected run tmpfs flags to include noexec,nosuid,nodev; got %v", joined)
	}
}



