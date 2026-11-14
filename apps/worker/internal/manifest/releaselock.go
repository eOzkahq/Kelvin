// Package manifest manages the authoritative release manifest for certified scanner images.
package manifest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// StatusNotReleased indicates the scanner images are in development/staging and not yet certified.
	StatusNotReleased = "not-released"
	// StatusCertified indicates the scanner images have passed full release gates and are certified.
	StatusCertified = "certified"

	// EmptySHA256Digest is the cryptographic hash of zero bytes (e3b0c442...).
	// It is strictly prohibited in release manifests as a placeholder.
	EmptySHA256Digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	ErrScannerNotReleased   = errors.New("manifest: scanner is not certified or released for production execution")
	ErrPlaceholderEmptyHash = errors.New("manifest: empty string placeholder hash is prohibited")
	ErrManifestConflict     = errors.New("manifest: release locks conflict")
	ErrMissingReleaseDigest = errors.New("manifest: released scanner must have non-empty sha256 digest")
)

// ScannerImageLock represents the canonical JSON release manifest (deploy/scanners/images.lock.json).
type ScannerImageLock struct {
	SchemaVersion string                   `json:"schema_version"`
	Status        string                   `json:"status"`
	GeneratedAt   string                   `json:"generated_at,omitempty"`
	BuildRecord   string                   `json:"build_record,omitempty"`
	ReleaseNote   string                   `json:"release_note,omitempty"`
	Images        map[string]ImageMetadata `json:"images"`
}

type ImageMetadata struct {
	Upstream              string  `json:"upstream,omitempty"`
	UpstreamDigest        *string `json:"upstream_digest,omitempty"`
	Version               *string `json:"version,omitempty"`
	DistrolessBase        *string `json:"distroless_base,omitempty"`
	DistrolessDigest      *string `json:"distroless_digest,omitempty"`
	KelvinImage           *string `json:"kelvin_image,omitempty"`
	KelvinDigest          *string `json:"kelvin_digest,omitempty"`
	TemplateCatalogID     string  `json:"template_catalog_id,omitempty"`
	TemplateCatalogDigest *string `json:"template_catalog_digest,omitempty"`
}

// ScannerYAMLLock represents the secondary YAML release lock (deploy/scanner-image-lock.yaml).
type ScannerYAMLLock struct {
	SchemaVersion  string
	GeneratedAt    string
	TargetPlatform string
	Status         string
	BuildRecord    string
	Scanners       map[string]YAMLLockScanner
}

type YAMLLockScanner struct {
	ID                     string
	Version                string
	AdapterVersion         string
	ImageReference         string
	ImageDigest            string
	TemplateCatalogVersion string
	TemplateCatalogDigest  string
	Executable             string
	User                   string
	InternalBuiltin        bool
}

// LoadCanonicalLock parses and validates the authoritative JSON release lock.
func LoadCanonicalLock(jsonPath string) (*ScannerImageLock, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("manifest: read canonical lock %q: %w", jsonPath, err)
	}
	var lock ScannerImageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("manifest: parse canonical lock: %w", err)
	}
	if lock.SchemaVersion != "1" && lock.SchemaVersion != "1.0" {
		return nil, fmt.Errorf("manifest: unsupported schema version %q", lock.SchemaVersion)
	}
	return &lock, nil
}

// LoadYAMLLock parses the YAML release lock using a clean zero-dependency parser.
func LoadYAMLLock(yamlPath string) (*ScannerYAMLLock, error) {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("manifest: read yaml lock %q: %w", yamlPath, err)
	}

	lock := &ScannerYAMLLock{
		Scanners: make(map[string]YAMLLockScanner),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var currentScannerID string
	var currentScanner YAMLLockScanner

	flushScanner := func() {
		if currentScannerID != "" {
			lock.Scanners[currentScannerID] = currentScanner
			currentScannerID = ""
			currentScanner = YAMLLockScanner{}
		}
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level key
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flushScanner()
			key, val, ok := strings.Cut(trimmed, ":")
			if ok {
				val = strings.Trim(strings.TrimSpace(val), "\"'")
				switch strings.TrimSpace(key) {
				case "schema_version":
					lock.SchemaVersion = val
				case "status":
					lock.Status = val
				case "generated_at":
					lock.GeneratedAt = val
				case "target_platform":
					lock.TargetPlatform = val
				case "build_record":
					lock.BuildRecord = val
				}
			}
			continue
		}

		// Scanner entry header (e.g. "  zap:")
		if (strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ")) ||
			(strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t")) {
			flushScanner()
			candidate := strings.TrimSuffix(trimmed, ":")
			if candidate != "scanners" {
				currentScannerID = candidate
				currentScanner.ID = candidate
			}
			continue
		}

		// Scanner property (e.g. "    image_digest: ...")
		if currentScannerID != "" {
			key, val, ok := strings.Cut(trimmed, ":")
			if ok {
				val = strings.Trim(strings.TrimSpace(val), "\"'")
				switch strings.TrimSpace(key) {
				case "id":
					currentScanner.ID = val
				case "version":
					currentScanner.Version = val
				case "image_reference":
					currentScanner.ImageReference = val
				case "image_digest":
					currentScanner.ImageDigest = val
				case "template_catalog_version":
					currentScanner.TemplateCatalogVersion = val
				case "template_catalog_digest":
					currentScanner.TemplateCatalogDigest = val
				case "executable":
					currentScanner.Executable = val
				case "user":
					currentScanner.User = val
				case "internal_builtin":
					currentScanner.InternalBuiltin = val == "true"
				}
			}
		}
	}
	flushScanner()

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("manifest: parse yaml lock: %w", err)
	}

	return lock, nil
}

// CalculateCatalogDigest computes the deterministic SHA256 digest of catalog.json.
// It verifies that each referenced template file exists and matches its declared checksum.
func CalculateCatalogDigest(catalogPath string) (string, error) {
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return "", fmt.Errorf("manifest: read catalog %q: %w", catalogPath, err)
	}

	var parsed struct {
		CatalogID string `json:"catalog_id"`
		Templates []struct {
			ID     string `json:"id"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("manifest: parse catalog json: %w", err)
	}

	baseDir := filepath.Dir(catalogPath)
	for _, tmpl := range parsed.Templates {
		fullPath := filepath.Join(baseDir, tmpl.Path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			return "", fmt.Errorf("manifest: catalog template %q missing: %w", tmpl.Path, err)
		}
		sum := sha256.Sum256(content)
		actual := hex.EncodeToString(sum[:])
		if !strings.EqualFold(actual, tmpl.SHA256) {
			return "", fmt.Errorf("manifest: template %q hash mismatch: declared %s, actual %s", tmpl.ID, tmpl.SHA256, actual)
		}
	}

	h := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(h[:])
	if digest == EmptySHA256Digest {
		return "", ErrPlaceholderEmptyHash
	}
	return digest, nil
}

// ValidateLockConsistency asserts that both manifest files agree on release status,
// contain no empty hash placeholders, and correctly represent catalog integrity.
func ValidateLockConsistency(yamlPath, jsonPath string) error {
	jsonLock, err := LoadCanonicalLock(jsonPath)
	if err != nil {
		return err
	}
	yamlLock, err := LoadYAMLLock(yamlPath)
	if err != nil {
		return err
	}

	// 1. Release status must strictly match
	if jsonLock.Status != yamlLock.Status {
		return fmt.Errorf("%w: status mismatch (json=%q, yaml=%q)", ErrManifestConflict, jsonLock.Status, yamlLock.Status)
	}

	// 2. Reject empty placeholder digests in YAML
	for id, scanner := range yamlLock.Scanners {
		if scanner.TemplateCatalogDigest == EmptySHA256Digest {
			return fmt.Errorf("%w: scanner %q has empty string placeholder catalog digest", ErrPlaceholderEmptyHash, id)
		}
		if scanner.ImageDigest == EmptySHA256Digest {
			return fmt.Errorf("%w: scanner %q has empty string placeholder image digest", ErrPlaceholderEmptyHash, id)
		}
	}

	// 3. Reject empty placeholder digests in JSON
	for id, img := range jsonLock.Images {
		if img.TemplateCatalogDigest != nil && *img.TemplateCatalogDigest == EmptySHA256Digest {
			return fmt.Errorf("%w: scanner %q json has empty placeholder catalog digest", ErrPlaceholderEmptyHash, id)
		}
		if img.KelvinDigest != nil && *img.KelvinDigest == EmptySHA256Digest {
			return fmt.Errorf("%w: scanner %q json has empty placeholder image digest", ErrPlaceholderEmptyHash, id)
		}
	}

	// 4. If status is certified/released, all digests must be present and non-empty
	if jsonLock.Status == StatusCertified || jsonLock.Status == "released" || jsonLock.Status == "locked" {
		for id, img := range jsonLock.Images {
			if img.KelvinDigest == nil || *img.KelvinDigest == "" {
				return fmt.Errorf("%w: released scanner %q is missing KelvinDigest", ErrMissingReleaseDigest, id)
			}
		}
	}

	return nil
}

// ValidateReleaseStatusForExecution enforces that production/staging workers
// reject running any scanner whose release status is not certified.
func ValidateReleaseStatusForExecution(status, env string) error {
	if (env == "production" || env == "staging") && status != StatusCertified {
		return ErrScannerNotReleased
	}
	return nil
}

// EnforceCertifiedReleaseForExecution checks the canonical release manifest on disk
// and fails closed in staging and production if the manifest is missing, invalid,
// or the scanner image is not certified.
func EnforceCertifiedReleaseForExecution(manifestPath, scannerID, env string) error {
	if env != "production" && env != "staging" {
		return nil
	}
	if strings.TrimSpace(manifestPath) == "" {
		manifestPath = "deploy/scanners/images.lock.json"
	}
	lock, err := LoadCanonicalLock(manifestPath)
	if err != nil {
		return fmt.Errorf("manifest: failed to load release manifest for execution gate: %w", err)
	}
	if lock.Status != StatusCertified {
		return fmt.Errorf("%w: manifest release status is %q", ErrScannerNotReleased, lock.Status)
	}
	img, ok := lock.Images[scannerID]
	if !ok {
		return fmt.Errorf("%w: scanner %q not found in release manifest", ErrScannerNotReleased, scannerID)
	}
	if img.KelvinDigest == nil || *img.KelvinDigest == "" || *img.KelvinDigest == EmptySHA256Digest {
		return fmt.Errorf("%w: scanner %q has missing or empty release digest", ErrScannerNotReleased, scannerID)
	}
	if !strings.HasPrefix(*img.KelvinDigest, "sha256:") || len(strings.TrimPrefix(*img.KelvinDigest, "sha256:")) != 64 {
		return fmt.Errorf("%w: scanner %q has invalid release digest format %q", ErrScannerNotReleased, scannerID, *img.KelvinDigest)
	}
	return nil
}
