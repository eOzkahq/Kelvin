package adapters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCuratedCatalogManifestLoadsAndValidates(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "templates", "kelvin.safe.web.v1", "catalog.json")
	manifest, digest, err := LoadCuratedCatalog(manifestPath)
	if err != nil {
		t.Fatalf("failed to load curated catalog: %v", err)
	}

	if manifest.CatalogID != "kelvin.safe.web.v1" {
		t.Errorf("expected catalog ID kelvin.safe.web.v1, got %s", manifest.CatalogID)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Errorf("invalid digest format: %s", digest)
	}
	if len(manifest.Templates) < 4 {
		t.Errorf("expected at least 4 curated templates, got %d", len(manifest.Templates))
	}

	if !manifest.IsTemplateAllowed("git-config") {
		t.Errorf("expected git-config to be allowed")
	}
	if !manifest.IsTemplateAllowed("env-file") {
		t.Errorf("expected env-file to be allowed")
	}
	if manifest.IsTemplateAllowed("cve-2021-44228") {
		t.Errorf("unreviewed exploit template should not be allowed in curated safe web v1")
	}
	if manifest.IsTemplateAllowed("../../etc/passwd") {
		t.Errorf("arbitrary path traversal should not be allowed")
	}
}

func TestCuratedCatalogRejectsTamperedTemplate(t *testing.T) {
	dir := t.TempDir()
	tmplDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(tmplDir, 0755); err != nil {
		t.Fatal(err)
	}

	tmplPath := filepath.Join(tmplDir, "sample.yaml")
	if err := os.WriteFile(tmplPath, []byte("id: sample\n"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := CuratedCatalogManifest{
		SchemaVersion: "1",
		CatalogID:     "kelvin.safe.web.v1",
		Version:       "1.0.0",
		ReviewPolicy: CatalogReviewPolicy{
			Status:   "approved",
			Reviewer: "sec",
		},
		Templates: []CuratedTemplate{
			{
				ID:           "sample",
				Path:         "templates/sample.yaml",
				Severity:     "low",
				Category:     "discovery",
				Methods:      []string{"GET"},
				ReviewStatus: "approved",
				SHA256:       "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	if err := manifest.Validate(dir); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestCuratedCatalogRejectsIntrusivePolicies(t *testing.T) {
	manifest := CuratedCatalogManifest{
		SchemaVersion: "1",
		CatalogID:     "kelvin.safe.web.v1",
		Version:       "1.0.0",
		ReviewPolicy: CatalogReviewPolicy{
			Status:                 "approved",
			Reviewer:               "sec",
			IntrusiveChecksAllowed: true,
		},
		Templates: []CuratedTemplate{
			{
				ID:           "sample",
				ReviewStatus: "approved",
			},
		},
	}

	if err := manifest.Validate(""); err == nil {
		t.Fatal("expected intrusive policy rejection")
	}
}

func TestCuratedCatalogRejectsStateChangingMethods(t *testing.T) {
	manifest := CuratedCatalogManifest{
		SchemaVersion: "1",
		CatalogID:     "kelvin.safe.web.v1",
		Version:       "1.0.0",
		ReviewPolicy: CatalogReviewPolicy{
			Status:   "approved",
			Reviewer: "sec",
		},
		Templates: []CuratedTemplate{
			{
				ID:           "sample",
				Methods:      []string{"POST"},
				ReviewStatus: "approved",
			},
		},
	}

	if err := manifest.Validate(""); err == nil {
		t.Fatal("expected POST method rejection")
	}
}
