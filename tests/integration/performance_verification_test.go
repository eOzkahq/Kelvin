package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPerformanceVerification validates the load test scripts, k6 test definitions,
// and performance benchmark report.
func TestPerformanceVerification(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify k6 load test script
	k6Path := filepath.Join(repoRoot, "tests", "performance", "load-test.js")
	data, err := os.ReadFile(k6Path)
	if err != nil {
		t.Fatalf("Missing tests/performance/load-test.js: %v", err)
	}
	k6Content := string(data)

	if !strings.Contains(k6Content, "baseline_load") {
		t.Errorf("load-test.js missing baseline_load scenario")
	}
	if !strings.Contains(k6Content, "stress_spike") {
		t.Errorf("load-test.js missing stress_spike scenario")
	}
	if !strings.Contains(k6Content, "p(95)<250") {
		t.Errorf("load-test.js must verify p95 < 250ms latency threshold")
	}

	// 2. Verify test runner safety check against production domains
	runnerPath := filepath.Join(repoRoot, "scripts", "testing", "run-load-stress-tests.sh")
	data, err = os.ReadFile(runnerPath)
	if err != nil {
		t.Fatalf("Missing scripts/testing/run-load-stress-tests.sh: %v", err)
	}
	runnerContent := string(data)

	if !strings.Contains(runnerContent, "kelvinsecurity\\.io") {
		t.Errorf("run-load-stress-tests.sh must contain safety check against public production URLs")
	}

	// 3. Verify Performance Benchmark Documentation
	docPath := filepath.Join(repoRoot, "docs", "performance", "LOAD_STRESS_AND_SOAK_TEST_REPORT.md")
	data, err = os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("Missing LOAD_STRESS_AND_SOAK_TEST_REPORT.md: %v", err)
	}
	docContent := string(data)

	for _, req := range []string{"Baseline Load", "Stress Spike", "Soak Test", "Throughput (RPS)", "Optimization Recommendations"} {
		if !strings.Contains(docContent, req) {
			t.Errorf("LOAD_STRESS_AND_SOAK_TEST_REPORT.md missing required section: %s", req)
		}
	}
}
