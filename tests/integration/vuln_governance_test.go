package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type VulnerabilityException struct {
	ID                   string   `json:"id"`
	CveID                string   `json:"cve_id"`
	Package              string   `json:"package"`
	AffectedVersions     string   `json:"affected_versions"`
	Severity             string   `json:"severity"`
	CVSS                 float64  `json:"cvss"`
	Justification        string   `json:"justification"`
	CompensatingControls []string `json:"compensating_controls"`
	RequestedBy          string   `json:"requested_by"`
	ApprovedBy           string   `json:"approved_by"`
	CreatedAt            string   `json:"created_at"`
	ExpiresAt            string   `json:"expires_at"`
	Status               string   `json:"status"`
}

type VulnerabilityExceptionFile struct {
	Version      string                   `json:"version"`
	LastReviewed string                   `json:"last_reviewed"`
	Exceptions   []VulnerabilityException `json:"exceptions"`
}

// GetRemediationTargetDuration returns the maximum permissible time to remediate a CVE based on CVSS score.
func GetRemediationTargetDuration(cvss float64) time.Duration {
	switch {
	case cvss >= 9.0:
		return 24 * time.Hour // Critical: 24h
	case cvss >= 7.0:
		return 7 * 24 * time.Hour // High: 7 days
	case cvss >= 4.0:
		return 30 * 24 * time.Hour // Medium: 30 days
	default:
		return 90 * 24 * time.Hour // Low: 90 days
	}
}

// IsScannerEngineEnabled checks whether a third-party scanner has been emergency disabled.
func IsScannerEngineEnabled(engineName string) bool {
	envKey := "WORKER_SCANNER_" + engineName + "_ENABLED"
	val := os.Getenv(envKey)
	return val != "false"
}

func TestVulnerabilityGovernance_ExceptionValidation(t *testing.T) {
	// Locate docs/security/vulnerability-exceptions.json
	repoRoot := filepath.Join("..", "..")
	filePath := filepath.Join(repoRoot, "docs", "security", "vulnerability-exceptions.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read vulnerability-exceptions.json: %v", err)
	}

	var parsed VulnerabilityExceptionFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse vulnerability-exceptions.json: %v", err)
	}

	if len(parsed.Exceptions) == 0 {
		t.Log("Note: Zero active vulnerability exceptions recorded.")
		return
	}

	now := time.Now().UTC()

	for _, exc := range parsed.Exceptions {
		t.Run("Exception_"+exc.ID, func(t *testing.T) {
			if exc.ID == "" || exc.CveID == "" {
				t.Errorf("Exception missing ID or CveID: %+v", exc)
			}
			if exc.Justification == "" {
				t.Errorf("Exception %s missing technical justification", exc.ID)
			}
			if len(exc.CompensatingControls) == 0 {
				t.Errorf("Exception %s must specify at least one compensating control", exc.ID)
			}
			if exc.ApprovedBy == "" {
				t.Errorf("Exception %s missing approved_by authority", exc.ID)
			}

			// Validate timestamps
			createdAt, err := time.Parse(time.RFC3339, exc.CreatedAt)
			if err != nil {
				t.Fatalf("Invalid created_at timestamp in %s: %v", exc.ID, err)
			}
			expiresAt, err := time.Parse(time.RFC3339, exc.ExpiresAt)
			if err != nil {
				t.Fatalf("Invalid expires_at timestamp in %s: %v", exc.ID, err)
			}

			// Max 30-day exception rule
			duration := expiresAt.Sub(createdAt)
			if duration > 31*24*time.Hour {
				t.Errorf("Exception %s duration (%v) exceeds maximum allowable 30 days limit", exc.ID, duration)
			}

			// Verify not currently expired if marked APPROVED
			if exc.Status == "APPROVED" && now.After(expiresAt) {
				t.Errorf("Exception %s is EXPIRED (expired at %v, current time %v)", exc.ID, expiresAt, now)
			}
		})
	}
}

func TestVulnerabilityGovernance_RemediationSLAs(t *testing.T) {
	cases := []struct {
		cvss     float64
		expected time.Duration
	}{
		{9.8, 24 * time.Hour},
		{9.0, 24 * time.Hour},
		{8.5, 7 * 24 * time.Hour},
		{7.0, 7 * 24 * time.Hour},
		{5.3, 30 * 24 * time.Hour},
		{4.0, 30 * 24 * time.Hour},
		{3.1, 90 * 24 * time.Hour},
		{0.0, 90 * 24 * time.Hour},
	}

	for _, tc := range cases {
		dur := GetRemediationTargetDuration(tc.cvss)
		if dur != tc.expected {
			t.Errorf("CVSS %.1f: expected SLA duration %v, got %v", tc.cvss, tc.expected, dur)
		}
	}
}

func TestVulnerabilityGovernance_ScannerEmergencyKillSwitch(t *testing.T) {
	// Verify default enabled
	if !IsScannerEngineEnabled("NUCLEI") {
		t.Errorf("Expected NUCLEI to be enabled by default")
	}

	// Set kill switch
	t.Setenv("WORKER_SCANNER_NUCLEI_ENABLED", "false")
	if IsScannerEngineEnabled("NUCLEI") {
		t.Errorf("Expected NUCLEI to be disabled when kill switch is set")
	}
}
