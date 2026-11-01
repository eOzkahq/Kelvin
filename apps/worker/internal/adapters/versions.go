package adapters

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// VersionPolicy pins the exact scanner runtime allowed by a registry entry.
// No ranges or mutable tags are accepted for runtime execution.
type VersionPolicy struct {
	ScannerVersion         string `json:"scanner_version"`
	ImageReference         string `json:"image_reference,omitempty"`
	ImageDigest            string `json:"image_digest,omitempty"`
	TemplateCatalogVersion string `json:"template_catalog_version,omitempty"`
	TemplateCatalogDigest  string `json:"template_catalog_digest,omitempty"`
}

// RuntimeVersionInfo is measured by the adapter from the actual runtime being
// used, not copied from the registry's expectation.
type RuntimeVersionInfo struct {
	ScannerVersion         string `json:"scanner_version"`
	AdapterVersion         string `json:"adapter_version"`
	ImageReference         string `json:"image_reference,omitempty"`
	ImageDigest            string `json:"image_digest,omitempty"`
	TemplateCatalogVersion string `json:"template_catalog_version,omitempty"`
	TemplateCatalogDigest  string `json:"template_catalog_digest,omitempty"`
}

// VersionVerifier is implemented by adapters that can inspect the actual
// executable/container runtime. The worker calls it during startup and before
// dispatch so mutable or unexpected runtimes fail closed.
type VersionVerifier interface {
	VerifyRuntimeVersion(context.Context) (RuntimeVersionInfo, error)
}

func validateVersionPolicy(id, adapterVersion string, caps Capabilities, policy VersionPolicy) error {
	if !semverPattern.MatchString(adapterVersion) {
		return fmt.Errorf("adapter version %q must be semantic version x.y.z", adapterVersion)
	}
	if strings.TrimSpace(policy.ScannerVersion) == "" || strings.EqualFold(policy.ScannerVersion, "latest") {
		return fmt.Errorf("scanner version must be pinned exactly")
	}
	if caps.RequiresSandbox {
		if policy.ImageReference == "" || !digestPattern.MatchString(policy.ImageDigest) {
			return fmt.Errorf("sandboxed scanner requires an immutable image reference and sha256 digest")
		}
		if !strings.HasSuffix(policy.ImageReference, "@"+policy.ImageDigest) {
			return fmt.Errorf("image reference must end with its pinned digest")
		}
	}
	if (policy.ImageReference == "") != (policy.ImageDigest == "") {
		return fmt.Errorf("image reference and digest must be supplied together")
	}
	if policy.ImageDigest != "" && !digestPattern.MatchString(policy.ImageDigest) {
		return fmt.Errorf("image digest must be a sha256 digest")
	}
	if id == ScannerNuclei {
		if policy.TemplateCatalogVersion != "kelvin.safe.web.v1" || !digestPattern.MatchString(policy.TemplateCatalogDigest) {
			return fmt.Errorf("nuclei requires the approved template catalog ID and sha256 digest")
		}
	}
	if (policy.TemplateCatalogVersion == "") != (policy.TemplateCatalogDigest == "") {
		return fmt.Errorf("template catalog version and digest must be supplied together")
	}
	if policy.TemplateCatalogDigest != "" && !digestPattern.MatchString(policy.TemplateCatalogDigest) {
		return fmt.Errorf("template catalog digest must be a sha256 digest")
	}
	return nil
}

func compareRuntimeVersion(id, adapterVersion string, policy VersionPolicy, actual RuntimeVersionInfo) error {
	if actual.AdapterVersion != adapterVersion {
		return fmt.Errorf("adapter version mismatch: expected %s, got %s", adapterVersion, actual.AdapterVersion)
	}
	if actual.ScannerVersion != policy.ScannerVersion {
		return fmt.Errorf("scanner version mismatch: expected %s, got %s", policy.ScannerVersion, actual.ScannerVersion)
	}
	if actual.ImageReference != policy.ImageReference || actual.ImageDigest != policy.ImageDigest {
		return fmt.Errorf("scanner image identity does not match pinned policy")
	}
	if actual.TemplateCatalogVersion != policy.TemplateCatalogVersion || actual.TemplateCatalogDigest != policy.TemplateCatalogDigest {
		return fmt.Errorf("scanner template catalog does not match pinned policy")
	}
	if id == ScannerNuclei && actual.TemplateCatalogVersion != "kelvin.safe.web.v1" {
		return fmt.Errorf("nuclei runtime did not report the approved template catalog")
	}
	return nil
}
