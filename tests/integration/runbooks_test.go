package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIncidentResponseAndRunbooks verifies that all operational runbooks,
// incident severity definitions, and simulation scripts exist and meet operational baselines.
func TestIncidentResponseAndRunbooks(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify Incident Response Framework
	fwPath := filepath.Join(repoRoot, "docs", "operations", "INCIDENT_RESPONSE_FRAMEWORK.md")
	data, err := os.ReadFile(fwPath)
	if err != nil {
		t.Fatalf("Missing INCIDENT_RESPONSE_FRAMEWORK.md: %v", err)
	}
	content := string(data)

	for _, sev := range []string{"SEV-0", "SEV-1", "SEV-2", "SEV-3"} {
		if !strings.Contains(content, sev) {
			t.Errorf("INCIDENT_RESPONSE_FRAMEWORK.md missing severity definition: %s", sev)
		}
	}

	// 2. Verify Runbooks Catalog
	runbooksDir := filepath.Join(repoRoot, "docs", "operations", "runbooks")
	requiredRunbooks := []string{
		"README.md",
		"RB-01_API_UNAVAILABILITY.md",
		"RB-02_WORKER_AND_QUEUE_FAILURE.md",
		"RB-03_DATABASE_FAILOVER_AND_POOLING.md",
		"RB-04_CREDENTIAL_COMPROMISE_AND_REVOCATION.md",
		"RB-05_TENANT_ISOLATION_BREACH.md",
		"RB-06_ABNORMAL_ASSESSMENT_KILL_SWITCH.md",
	}

	for _, rb := range requiredRunbooks {
		p := filepath.Join(runbooksDir, rb)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("Expected operational runbook %s does not exist", rb)
		}
	}

	// 3. Verify Simulation Script
	simScript := filepath.Join(repoRoot, "scripts", "operations", "simulate-incident.sh")
	if _, err := os.Stat(simScript); os.IsNotExist(err) {
		t.Errorf("Missing scripts/operations/simulate-incident.sh")
	}
}
