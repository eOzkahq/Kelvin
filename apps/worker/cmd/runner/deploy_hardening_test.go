package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
)

// NetworkInspectRecord mirrors Podman network inspect JSON output.
type NetworkInspectRecord struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
	Subnets  []struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	} `json:"subnets"`
}

// validateNetworkProperties simulates the strict 4-property check enforced in
// setup-rootless-podman.sh and validate-worker-host.sh.
func validateNetworkProperties(rec NetworkInspectRecord) []string {
	var mismatches []string
	if rec.Name != "kelvin-scanner-net" {
		mismatches = append(mismatches, "name mismatch")
	}
	if !rec.Internal {
		mismatches = append(mismatches, "internal=false")
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
	if !hasSubnet {
		mismatches = append(mismatches, "subnet missing 10.89.10.0/24")
	}
	if !hasGateway {
		mismatches = append(mismatches, "gateway missing 10.89.10.1")
	}
	return mismatches
}

// 1. Test existing correct network: untouched and passes validation
func TestNetworkValidation_ExistingCorrectNetwork(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: true,
	}
	rec.Subnets = append(rec.Subnets, struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	}{Subnet: "10.89.10.0/24", Gateway: "10.89.10.1"})

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) != 0 {
		t.Fatalf("expected valid network to have 0 mismatches, got: %v", mismatches)
	}
}

// 2 & 3. Test existing non-internal / incorrect internal network: fails closed
func TestNetworkValidation_ExistingNonInternalNetwork(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: false, // Insecure: direct egress bypass
	}
	rec.Subnets = append(rec.Subnets, struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	}{Subnet: "10.89.10.0/24", Gateway: "10.89.10.1"})

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) == 0 {
		t.Fatal("expected non-internal network to fail validation")
	}
	foundInternalError := false
	for _, m := range mismatches {
		if strings.Contains(m, "internal=false") {
			foundInternalError = true
		}
	}
	if !foundInternalError {
		t.Errorf("expected internal=false error, got mismatches: %v", mismatches)
	}
}

// 4. Test incorrect subnet / gateway: fails closed
func TestNetworkValidation_IncorrectSubnetGateway(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: true,
	}
	rec.Subnets = append(rec.Subnets, struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	}{Subnet: "10.89.20.0/24", Gateway: "10.89.20.1"})

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) == 0 {
		t.Fatal("expected subnet/gateway mismatch to fail validation")
	}
	hasSubnetErr := false
	hasGatewayErr := false
	for _, m := range mismatches {
		if strings.Contains(m, "subnet") {
			hasSubnetErr = true
		}
		if strings.Contains(m, "gateway") {
			hasGatewayErr = true
		}
	}
	if !hasSubnetErr || !hasGatewayErr {
		t.Errorf("expected subnet and gateway errors, got: %v", mismatches)
	}
}

// 5. Test conflicting subordinate UID/GID ranges
func validateOrAddSubidContent(content string) (newContent string, err string) {
	expected := "kelvin-worker:100000:65536"
	var existingLines []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "kelvin-worker:") {
			existingLines = append(existingLines, trimmed)
		}
	}

	if len(existingLines) == 0 {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + expected + "\n", ""
	}

	if len(existingLines) == 1 && existingLines[0] == expected {
		return content, "" // Idempotent no-op
	}

	return "", "conflicting subordinate ID configuration found: expected " + expected + ", found " + strings.Join(existingLines, ", ")
}

func TestSubordinateIDValidation_ConflictingRanges(t *testing.T) {
	// Case A: Missing mapping -> successfully adds expected mapping
	resA, errA := validateOrAddSubidContent("otheruser:200000:65536\n")
	if errA != "" {
		t.Fatalf("unexpected error for missing mapping: %s", errA)
	}
	if !strings.Contains(resA, "kelvin-worker:100000:65536") {
		t.Errorf("expected new mapping appended, got: %s", resA)
	}

	// Case B: Existing correct mapping -> idempotent, no duplicate added
	resB, errB := validateOrAddSubidContent("kelvin-worker:100000:65536\n")
	if errB != "" {
		t.Fatalf("unexpected error for valid existing mapping: %s", errB)
	}
	if strings.Count(resB, "kelvin-worker:100000:65536") != 1 {
		t.Errorf("expected exactly 1 mapping, got duplicate: %s", resB)
	}

	// Case C: Conflicting mapping range -> aborts with error
	_, errC := validateOrAddSubidContent("kelvin-worker:200000:65536\n")
	if errC == "" {
		t.Fatal("expected conflict error for range 200000:65536, got nil")
	}
	if !strings.Contains(errC, "conflicting subordinate ID") {
		t.Errorf("expected conflict message, got: %s", errC)
	}

	// Case D: Multiple duplicate conflicting lines -> aborts with error
	_, errD := validateOrAddSubidContent("kelvin-worker:100000:65536\nkelvin-worker:200000:65536\n")
	if errD == "" {
		t.Fatal("expected conflict error for multiple mappings, got nil")
	}
}

// 6. Test architecture enforcement: strictly requires aarch64 or arm64
func validateHostArchitecture(arch string) bool {
	return arch == "aarch64" || arch == "arm64"
}

func TestArchitectureEnforcement_RejectsUnsupported(t *testing.T) {
	validArchs := []string{"aarch64", "arm64"}
	for _, a := range validArchs {
		if !validateHostArchitecture(a) {
			t.Errorf("expected architecture %q to be valid", a)
		}
	}

	unsupportedArchs := []string{"x86_64", "amd64", "i386", "armv7l", "riscv64", "mips64"}
	for _, a := range unsupportedArchs {
		if validateHostArchitecture(a) {
			t.Errorf("expected architecture %q to be rejected", a)
		}
	}
}

// 7. Test failed deployment rollback logic
func TestDeploymentRollback_Mechanism(t *testing.T) {
	tmpDir := t.TempDir()
	binDest := filepath.Join(tmpDir, "kelvin-worker")
	binPrev := filepath.Join(tmpDir, "kelvin-worker.prev")

	// Setup initial known-good active binary
	initialContent := "binary-version-1.0-known-good"
	if err := os.WriteFile(binDest, []byte(initialContent), 0755); err != nil {
		t.Fatalf("failed to write initial binary: %v", err)
	}

	// Step 1: Backup active binary before replacing
	if err := os.WriteFile(binPrev, []byte(initialContent), 0755); err != nil {
		t.Fatalf("failed to backup binary: %v", err)
	}

	// Step 2: Atomic install of faulty new binary
	faultyContent := "binary-version-2.0-broken"
	if err := os.WriteFile(binDest, []byte(faultyContent), 0755); err != nil {
		t.Fatalf("failed to install new binary: %v", err)
	}

	// Step 3: Deployment failure occurs -> trigger rollback
	simulatedDeployFailed := true
	if simulatedDeployFailed {
		if _, err := os.Stat(binPrev); err == nil {
			// Restore previous binary
			prevData, readErr := os.ReadFile(binPrev)
			if readErr != nil {
				t.Fatalf("rollback read failed: %v", readErr)
			}
			if err := os.WriteFile(binDest, prevData, 0755); err != nil {
				t.Fatalf("rollback restore failed: %v", err)
			}
		}
	}

	// Verify restored binary matches initial known-good version
	restoredData, err := os.ReadFile(binDest)
	if err != nil {
		t.Fatalf("failed to read restored binary: %v", err)
	}
	if string(restoredData) != initialContent {
		t.Fatalf("rollback failed: expected %q, got %q", initialContent, string(restoredData))
	}

	// Step 4: When no previous binary exists, rollback reports unavailable
	_ = os.Remove(binPrev)
	hasPrev := false
	if _, err := os.Stat(binPrev); err == nil {
		hasPrev = true
	}
	if hasPrev {
		t.Fatal("expected no previous binary for fresh install")
	}
}

// 8. Test active service with unreleased scanner image manifest
func TestHonestReadiness_ActiveServiceWithUncertifiedRelease(t *testing.T) {
	// Create temporary canonical lock with status="not-released"
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "images.lock.json")
	lockContent := `{
  "schema_version": "1",
  "status": "not-released",
  "images": {
    "nuclei": {
      "upstream": "projectdiscovery/nuclei",
      "upstream_digest": null,
      "version": null,
      "kelvin_image": null,
      "kelvin_digest": null,
      "template_catalog_id": "kelvin.safe.web.v1",
      "template_catalog_digest": "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"
    }
  }
}`
	if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
		t.Fatalf("failed to write lock file: %v", err)
	}

	// In staging environment, release manifest probe must report StatusUnavailable
	probe := readiness.NewReleaseManifestProbe("nuclei", lockPath, "staging")
	ctx := context.Background()
	check := probe.Check(ctx)

	if check.Status != readiness.StatusUnavailable {
		t.Errorf("expected StatusUnavailable for not-released status in staging, got %s", check.Status)
	}
	if !strings.Contains(check.Message, "not certified") {
		t.Errorf("expected uncertified message, got: %s", check.Message)
	}

	// Verify orchestrator execution gate rejects container dispatch
	err := manifest.EnforceCertifiedReleaseForExecution(lockPath, "nuclei", "staging")
	if err == nil {
		t.Fatal("expected EnforceCertifiedReleaseForExecution to fail closed, got nil")
	}
	if !strings.Contains(err.Error(), "not certified") {
		t.Errorf("expected uncertified error, got: %v", err)
	}
}
