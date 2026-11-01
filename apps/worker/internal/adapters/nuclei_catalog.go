package adapters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CuratedCatalogManifest defines the schema and metadata for a curated
// Nuclei template collection approved for execution in Kelvin.
type CuratedCatalogManifest struct {
	SchemaVersion string             `json:"schema_version"`
	CatalogID     string             `json:"catalog_id"`
	Version       string             `json:"version"`
	Description   string             `json:"description"`
	CreatedAt     string             `json:"created_at"`
	ReviewPolicy  CatalogReviewPolicy `json:"review_policy"`
	Templates     []CuratedTemplate   `json:"templates"`
}

type CatalogReviewPolicy struct {
	Status                       string `json:"status"`
	Reviewer                     string `json:"reviewer"`
	IntrusiveChecksAllowed       bool   `json:"intrusive_checks_allowed"`
	DOSChecksAllowed             bool   `json:"dos_checks_allowed"`
	ExploitPayloadsAllowed       bool   `json:"exploit_payloads_allowed"`
	StateChangingMethodsAllowed  bool   `json:"state_changing_methods_allowed"`
}

type CuratedTemplate struct {
	ID           string   `json:"id"`
	Path         string   `json:"path"`
	Severity     string   `json:"severity"`
	Category     string   `json:"category"`
	Methods      []string `json:"methods"`
	ReviewStatus string   `json:"review_status"`
	SHA256       string   `json:"sha256"`
}

// LoadCuratedCatalog reads and validates a catalog manifest from disk.
func LoadCuratedCatalog(manifestPath string) (*CuratedCatalogManifest, string, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, "", fmt.Errorf("adapters: load curated catalog: %w", err)
	}

	h := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(h[:])

	var manifest CuratedCatalogManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, "", fmt.Errorf("adapters: parse curated catalog: %w", err)
	}

	if err := manifest.Validate(filepath.Dir(manifestPath)); err != nil {
		return nil, "", err
	}

	return &manifest, digest, nil
}

// Validate verifies catalog invariants: approved review status, non-intrusive
// safety policy, template hash integrity, and absence of prohibited methods.
func (c *CuratedCatalogManifest) Validate(baseDir string) error {
	if c.SchemaVersion != "1" {
		return fmt.Errorf("adapters: unsupported catalog schema version %q", c.SchemaVersion)
	}
	if c.CatalogID != "kelvin.safe.web.v1" {
		return fmt.Errorf("adapters: unapproved catalog ID %q", c.CatalogID)
	}
	if c.ReviewPolicy.Status != "approved" {
		return fmt.Errorf("adapters: catalog review status is %q, want approved", c.ReviewPolicy.Status)
	}
	if c.ReviewPolicy.IntrusiveChecksAllowed || c.ReviewPolicy.DOSChecksAllowed ||
		c.ReviewPolicy.ExploitPayloadsAllowed || c.ReviewPolicy.StateChangingMethodsAllowed {
		return fmt.Errorf("adapters: catalog review policy violates non-intrusive safety invariant")
	}
	if len(c.Templates) == 0 {
		return fmt.Errorf("adapters: catalog contains no templates")
	}

	seenIDs := make(map[string]bool)
	for _, t := range c.Templates {
		if t.ID == "" {
			return fmt.Errorf("adapters: template ID cannot be empty")
		}
		if seenIDs[t.ID] {
			return fmt.Errorf("adapters: duplicate template ID %q in catalog", t.ID)
		}
		seenIDs[t.ID] = true

		if t.ReviewStatus != "approved" {
			return fmt.Errorf("adapters: template %q has unapproved status %q", t.ID, t.ReviewStatus)
		}
		for _, m := range t.Methods {
			upper := strings.ToUpper(m)
			if upper != "GET" && upper != "HEAD" && upper != "OPTIONS" {
				return fmt.Errorf("adapters: template %q uses disallowed method %q", t.ID, m)
			}
		}

		if baseDir != "" && t.Path != "" {
			targetPath := filepath.Join(baseDir, t.Path)
			content, err := os.ReadFile(targetPath)
			if err != nil {
				return fmt.Errorf("adapters: template file %q missing: %w", t.Path, err)
			}
			sum := sha256.Sum256(content)
			actualHash := hex.EncodeToString(sum[:])
			if !strings.EqualFold(actualHash, t.SHA256) {
				return fmt.Errorf("adapters: template %q checksum mismatch: expected %s, got %s", t.ID, t.SHA256, actualHash)
			}
		}
	}

	return nil
}

// IsTemplateAllowed checks whether the specified template ID exists in the
// curated catalog and is approved.
func (c *CuratedCatalogManifest) IsTemplateAllowed(templateID string) bool {
	if c == nil {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(templateID))
	for _, t := range c.Templates {
		if strings.ToLower(t.ID) == normalized && t.ReviewStatus == "approved" {
			return true
		}
	}
	return false
}
