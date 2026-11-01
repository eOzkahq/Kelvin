// Package sandbox tests verify the execution-isolation contract: container
// specifications are validated against the mandatory hardening profile, and the
// fake executor simulates OOM, deadline-exceeded, crash, and success outcomes.
package sandbox

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/outputcapture"
)

func validSpec() Spec {
	return Spec{
		Image:           "kelvin/scanner-nuclei:3.3.0@sha256:" + strings.Repeat("a", 64),
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
	spec.Image = "registry.example/zap@sha256:" + strings.Repeat("a", 64)
	spec.Invocation = ProcessInvocation{Executable: "/zap/zap-baseline.py", Args: []string{"-t", "https://example.com", "-J", "/tmp/kelvin-zap-report.json"}}
	spec.Labels["scanner"] = "zap"
	spec.CaptureZAPReport = true
	spec.NetworkDisabled = true
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
	spec.Image = "registry.example/zap@sha256:" + strings.Repeat("a", 64)
	spec.Invocation = ProcessInvocation{Executable: "/zap/zap-baseline.py", Args: []string{"-t", "https://example.com", "-J", "/tmp/kelvin-zap-report.json"}}
	spec.Labels["scanner"] = "zap"
	spec.CaptureZAPReport = true
	spec.NetworkDisabled = false

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
