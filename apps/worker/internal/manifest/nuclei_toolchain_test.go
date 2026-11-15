package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type toolchainLockFile struct {
	SchemaVersion string `json:"schema_version"`
	Toolchain     struct {
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		Image         string   `json:"image"`
		Digest        string   `json:"digest"`
		Architectures []string `json:"architectures"`
		CompilerFlags []string `json:"compiler_flags"`
	} `json:"toolchain"`
	RemediatedStdlibCVEs []struct {
		CVEID        string `json:"cve_id"`
		Component    string `json:"component"`
		FixedVersion string `json:"fixed_version"`
		Status       string `json:"status"`
		Advisory     string `json:"advisory"`
	} `json:"remediated_stdlib_cves"`
}

func TestNucleiToolchainLock_ReconciliationOfStdlibCVEs(t *testing.T) {
	lockPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", "toolchain.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read toolchain.lock: %v", err)
	}

	var lock toolchainLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("failed to parse toolchain.lock: %v", err)
	}

	// 1. Toolchain invariants
	if lock.Toolchain.Name != "golang" {
		t.Errorf("toolchain name must be golang, got: %q", lock.Toolchain.Name)
	}
	if lock.Toolchain.Version != "1.26.10" {
		t.Errorf("expected toolchain version 1.26.10, got: %q", lock.Toolchain.Version)
	}
	if lock.Toolchain.Digest != "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696" {
		t.Errorf("builder toolchain digest mismatch: %s", lock.Toolchain.Digest)
	}

	// 2. All 11 reported stdlib CVEs must be accounted for
	expectedCVEs := map[string]string{
		"CVE-2026-111943": "1.26.10",
		"CVE-2026-33818":  "1.26.6",
		"CVE-2026-39821":  "1.26.6",
		"CVE-2026-46600":  "1.26.6",
		"CVE-2026-56853":  "1.26.6",
		"CVE-2026-56858":  "1.26.6",
		"CVE-2026-56859":  "1.26.6",
		"CVE-2026-56860":  "1.26.6",
		"CVE-2026-56862":  "1.26.6",
		"CVE-2026-78667":  "1.26.9",
		"CVE-2026-97031":  "1.26.9",
	}

	if len(lock.RemediatedStdlibCVEs) != 11 {
		t.Fatalf("expected exactly 11 remediated stdlib CVEs, got: %d", len(lock.RemediatedStdlibCVEs))
	}

	foundCVEs := make(map[string]bool)
	for _, rec := range lock.RemediatedStdlibCVEs {
		foundCVEs[rec.CVEID] = true
		expFixed, ok := expectedCVEs[rec.CVEID]
		if !ok {
			t.Errorf("unexpected CVE %q in toolchain.lock", rec.CVEID)
			continue
		}
		if rec.FixedVersion != expFixed {
			t.Errorf("%s: expected fixed_version %s, got %s", rec.CVEID, expFixed, rec.FixedVersion)
		}
		if rec.Status != "remediated" {
			t.Errorf("%s: expected status 'remediated', got %q", rec.CVEID, rec.Status)
		}
		if !strings.HasPrefix(rec.Advisory, "https://") {
			t.Errorf("%s: invalid advisory URL %q", rec.CVEID, rec.Advisory)
		}
	}

	for expCVE := range expectedCVEs {
		if !foundCVEs[expCVE] {
			t.Errorf("missing reconciliation record for %s", expCVE)
		}
	}
}
