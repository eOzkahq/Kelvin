package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nucleiModulesLockFile struct {
	SchemaVersion        string `json:"schema_version"`
	RemediatedModuleCVEs []struct {
		CVEID        string `json:"cve_id"`
		Component    string `json:"component"`
		FixedVersion string `json:"fixed_version"`
		Status       string `json:"status"`
		Advisory     string `json:"advisory"`
	} `json:"remediated_module_cves"`
}

func TestNucleiGoModules_ReconciliationOf15ModuleCVEs(t *testing.T) {
	nucleiDir := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei")

	// 1. Read and parse modules.lock
	lockPath := filepath.Join(nucleiDir, "modules.lock")
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read modules.lock: %v", err)
	}

	var lock nucleiModulesLockFile
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatalf("failed to parse modules.lock: %v", err)
	}

	expectedCVEs := map[string]string{
		"CVE-2026-100349": "v0.148.0",
		"CVE-2026-100351": "v0.148.0",
		"CVE-2026-100352": "v0.148.0",
		"CVE-2026-100353": "v0.148.0",
		"CVE-2026-100354": "v0.148.0",
		"CVE-2026-116587": "v4.1.6",
		"CVE-2026-56851":  "v0.41.0",
		"CVE-2026-56854":  "v0.55.0",
		"CVE-2026-56864":  "v0.40.0",
		"CVE-2026-56865":  "v0.40.0",
		"CVE-2026-71556":  "v5.14.0",
		"CVE-2026-78661":  "v0.62.0",
		"CVE-2026-78669":  "v0.62.0",
		"CVE-2026-84304":  "v1.83.1",
		"CVE-2026-84445":  "v1.83.1",
	}

	if len(lock.RemediatedModuleCVEs) != 15 {
		t.Fatalf("expected exactly 15 remediated module CVEs, got %d", len(lock.RemediatedModuleCVEs))
	}

	foundCVEs := make(map[string]bool)
	for _, rec := range lock.RemediatedModuleCVEs {
		foundCVEs[rec.CVEID] = true
		expVersion, ok := expectedCVEs[rec.CVEID]
		if !ok {
			t.Errorf("unexpected module CVE in modules.lock: %s", rec.CVEID)
			continue
		}
		if rec.FixedVersion != expVersion {
			t.Errorf("%s: expected fixed_version %s, got %s", rec.CVEID, expVersion, rec.FixedVersion)
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

	// 2. Verify go.mod contains all 8 required replacements
	goModBytes, err := os.ReadFile(filepath.Join(nucleiDir, "go.mod"))
	if err != nil {
		t.Fatalf("failed to read go.mod: %v", err)
	}
	goMod := string(goModBytes)
	requiredReplacements := []string{
		"github.com/getkin/kin-openapi => github.com/getkin/kin-openapi v0.148.0",
		"github.com/go-git/go-git/v5 => github.com/go-git/go-git/v5 v5.14.0",
		"github.com/go-jose/go-jose/v4 => github.com/go-jose/go-jose/v4 v4.1.6",
		"golang.org/x/crypto => golang.org/x/crypto v0.55.0",
		"golang.org/x/mod => golang.org/x/mod v0.40.0",
		"golang.org/x/net => golang.org/x/net v0.62.0",
		"golang.org/x/text => golang.org/x/text v0.41.0",
		"google.golang.org/grpc => google.golang.org/grpc v1.83.1",
	}
	for _, req := range requiredReplacements {
		if !strings.Contains(goMod, req) {
			t.Errorf("go.mod missing expected replace directive: %s", req)
		}
	}

	// 3. Verify Dockerfile contains go-modules.patch application
	dockerfileBytes, err := os.ReadFile(filepath.Join(nucleiDir, "Dockerfile"))
	if err != nil {
		t.Fatalf("failed to read Dockerfile: %v", err)
	}
	dockerfile := string(dockerfileBytes)
	if !strings.Contains(dockerfile, "go-modules.patch") {
		t.Errorf("Dockerfile missing reference to go-modules.patch")
	}
}
