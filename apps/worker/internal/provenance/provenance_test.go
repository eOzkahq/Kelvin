package provenance_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/provenance"
	"go.uber.org/zap"
)

func TestCollectorProvenanceLifecycle(t *testing.T) {
	tenantID := uuid.New().String()
	assessmentID := uuid.New().String()
	runID := uuid.New().String()
	scannerID := "nuclei"
	correlationID := uuid.New().String()

	collector := provenance.NewCollector(tenantID, assessmentID, runID, scannerID, correlationID, 1, zap.NewNop())

	cmd := []string{"/nuclei", "-target", "https://example.com", "--header", "Authorization: Bearer my-secret-jwt"}
	env := []string{"PATH=/bin:/usr/bin", "KELVIN_API_KEY=secret-token-value"}

	collector.RecordStart(cmd, env)

	collector.RecordDiagnostic("info", "discovery", "TEMPLATES_LOADED", "loaded 42 safe templates", map[string]any{"count": 42})
	collector.RecordDiagnostic("warning", "execution", "SLOW_TARGET", "target response exceeded 2000ms: token=abc12345", nil)

	duration := 1500 * time.Millisecond
	collector.RecordCompletion(0, duration, 128*1024*1024, 15000, 45000)

	prov := collector.Provenance()

	if prov.TenantID != tenantID || prov.AssessmentID != assessmentID || prov.RunID != runID {
		t.Fatalf("unexpected provenance coordinates: %+v", prov)
	}
	if prov.ScannerID != scannerID || prov.CorrelationID != correlationID || prov.Attempt != 1 {
		t.Fatalf("unexpected scanner coordinates: %+v", prov)
	}
	if prov.ExitCode != 0 || prov.DurationMS != duration.Milliseconds() {
		t.Fatalf("unexpected completion status: exit=%d, duration=%d", prov.ExitCode, prov.DurationMS)
	}
	if prov.PeakMemoryBytes != 128*1024*1024 || prov.NetworkTxBytes != 15000 || prov.NetworkRxBytes != 45000 {
		t.Fatalf("unexpected resource stats: %+v", prov)
	}

	// Verify command-line secret redaction
	joinedCmd := strings.Join(prov.CommandLine, " ")
	if strings.Contains(joinedCmd, "my-secret-jwt") {
		t.Fatalf("command line secret was not redacted: %s", joinedCmd)
	}
	if !strings.Contains(joinedCmd, provenance.RedactedMarker) {
		t.Fatalf("expected RedactedMarker in command line: %s", joinedCmd)
	}

	// Verify environment variable secret redaction
	joinedEnv := strings.Join(prov.Environment, " ")
	if strings.Contains(joinedEnv, "secret-token-value") {
		t.Fatalf("environment secret was not redacted: %s", joinedEnv)
	}
	if !strings.Contains(joinedEnv, "KELVIN_API_KEY="+provenance.RedactedMarker) {
		t.Fatalf("expected KELVIN_API_KEY=[REDACTED], got: %s", joinedEnv)
	}

	// Verify diagnostic message redaction
	if len(prov.Diagnostics) != 2 {
		t.Fatalf("expected 2 diagnostics, got %d", len(prov.Diagnostics))
	}
	if strings.Contains(prov.Diagnostics[1].Message, "abc12345") {
		t.Fatalf("diagnostic message token was not redacted: %s", prov.Diagnostics[1].Message)
	}

	// Verify conversion to ExecutionDiagnostic
	execDiags := collector.ToExecutionDiagnostics()
	if len(execDiags) != 2 {
		t.Fatalf("expected 2 ExecutionDiagnostics, got %d", len(execDiags))
	}
	if execDiags[0].Code != "TEMPLATES_LOADED" || execDiags[1].Code != "SLOW_TARGET" {
		t.Fatalf("unexpected ExecutionDiagnostic codes: %+v", execDiags)
	}
}

func TestRedactCommandLineFlags(t *testing.T) {
	args := []string{
		"scanner",
		"-H", "X-Api-Key: secret123",
		"--token", "secret-token-value",
		"-u", "https://example.com?api_key=querysecret",
	}

	redacted := provenance.RedactCommandLine(args)
	joined := strings.Join(redacted, " ")

	if strings.Contains(joined, "secret123") || strings.Contains(joined, "secret-token-value") || strings.Contains(joined, "querysecret") {
		t.Fatalf("secrets were not properly redacted: %s", joined)
	}
}

func TestRedactEnvironment(t *testing.T) {
	env := []string{
		"PUBLIC_HOST=example.com",
		"AWS_SECRET_ACCESS_KEY=my-aws-secret",
		"DATABASE_PASSWORD=superpassword",
		"AUTH_HEADER=Bearer tokenxyz",
	}

	redacted := provenance.RedactEnvironment(env)
	joined := strings.Join(redacted, " ")

	if strings.Contains(joined, "my-aws-secret") || strings.Contains(joined, "superpassword") || strings.Contains(joined, "tokenxyz") {
		t.Fatalf("environment secrets were not redacted: %s", joined)
	}
	if !strings.Contains(joined, "PUBLIC_HOST=example.com") {
		t.Fatalf("safe environment variable was corrupted: %s", joined)
	}
}
