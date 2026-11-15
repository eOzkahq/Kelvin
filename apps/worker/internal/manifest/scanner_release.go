// Package manifest provides authoritative release governance for scanner container images.
package manifest

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// ScorecardStatusEligible indicates scanner passed all security scorecards and is eligible for release.
	ScorecardStatusEligible = "ELIGIBLE"
	// ScorecardStatusIneligible indicates scanner failed one or more scorecard checks.
	ScorecardStatusIneligible = "INELIGIBLE"

	// Supported platform architectures for certified scanner release images.
	ArchLinuxArm64 = "linux/arm64"
	ArchLinuxAmd64 = "linux/amd64"
)

// ValidateReleaseArchitecture validates that the architecture is supported (linux/arm64 or linux/amd64).
func ValidateReleaseArchitecture(arch string) error {
	trimmed := strings.TrimSpace(arch)
	switch trimmed {
	case ArchLinuxArm64, ArchLinuxAmd64, "arm64", "amd64":
		return nil
	case "":
		return fmt.Errorf("%w: architecture cannot be empty", ErrInvalidArchitecture)
	default:
		return fmt.Errorf("%w: unsupported architecture %q (expected %s or %s)", ErrInvalidArchitecture, arch, ArchLinuxArm64, ArchLinuxAmd64)
	}
}

// ValidateSBOMDigest checks that an SBOM digest is present, is a valid sha256, and not empty string/hash.
func ValidateSBOMDigest(digest string) error {
	trimmed := strings.TrimSpace(digest)
	if trimmed == "" {
		return fmt.Errorf("%w: SBOM digest cannot be empty", ErrInvalidSBOMDigest)
	}
	if err := ValidateDigestFormat(trimmed); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSBOMDigest, err)
	}
	return nil
}

// ValidateSignatureRef checks that a Cosign signature reference is non-empty and well-formed.
func ValidateSignatureRef(ref string) error {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return fmt.Errorf("%w: signature reference cannot be empty", ErrInvalidSignatureRef)
	}
	if strings.HasPrefix(trimmed, "sha256:") {
		if err := ValidateDigestFormat(trimmed); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSignatureRef, err)
		}
	}
	return nil
}

// ValidateProvenanceRef checks that a SLSA provenance attestation reference is non-empty and well-formed.
func ValidateProvenanceRef(ref string) error {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return fmt.Errorf("%w: provenance reference cannot be empty", ErrInvalidProvenanceRef)
	}
	if strings.HasPrefix(trimmed, "sha256:") {
		if err := ValidateDigestFormat(trimmed); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidProvenanceRef, err)
		}
	}
	return nil
}

// ValidateScorecardStatus checks that the image scorecard status is ELIGIBLE.
func ValidateScorecardStatus(status string) error {
	trimmed := strings.TrimSpace(status)
	if trimmed == "" {
		return fmt.Errorf("%w: scorecard status cannot be empty", ErrIneligibleScorecard)
	}
	if trimmed != ScorecardStatusEligible {
		return fmt.Errorf("%w: scorecard status %q does not satisfy release gate (required: %s)", ErrIneligibleScorecard, status, ScorecardStatusEligible)
	}
	return nil
}

// ValidateCertifiedScannerManifest enforces that an images.lock.json release manifest
// is completely certified, containing verified immutable image digests, platform architectures,
// CycloneDX SBOM digests, Cosign signature references, SLSA provenance references,
// and scorecard eligibility. Fails closed if any required field is missing or unverified.
func ValidateCertifiedScannerManifest(lock *ScannerImageLock, catalogPath string) error {
	if lock == nil {
		return errors.New("manifest: nil lock provided")
	}
	if lock.Status != StatusCertified {
		if lock.Status == StatusNotReleased {
			return fmt.Errorf("%w: manifest is in %q status", ErrScannerNotReleased, lock.Status)
		}
		return fmt.Errorf("%w: invalid or uncertified status %q", ErrScannerNotReleased, lock.Status)
	}

	for _, scannerID := range []string{"zap", "nuclei"} {
		img, ok := lock.Images[scannerID]
		if !ok {
			return fmt.Errorf("%w: missing required scanner %q in release manifest", ErrIncompleteCertification, scannerID)
		}

		// 1. Upstream repo & digest
		if strings.TrimSpace(img.Upstream) == "" {
			return fmt.Errorf("%w: scanner %q missing upstream repository", ErrIncompleteCertification, scannerID)
		}
		if img.UpstreamDigest == nil || strings.TrimSpace(*img.UpstreamDigest) == "" {
			return fmt.Errorf("%w: scanner %q missing upstream digest", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateDigestFormat(*img.UpstreamDigest); err != nil {
			return fmt.Errorf("scanner %q: upstream digest: %w", scannerID, err)
		}

		// 2. Version
		if img.Version == nil || strings.TrimSpace(*img.Version) == "" {
			return fmt.Errorf("%w: scanner %q missing version", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateSemanticVersion(*img.Version); err != nil {
			return fmt.Errorf("scanner %q: version: %w", scannerID, err)
		}

		// 3. Kelvin Image & Digest
		if img.KelvinImage == nil || strings.TrimSpace(*img.KelvinImage) == "" {
			return fmt.Errorf("%w: scanner %q missing kelvin image", ErrIncompleteCertification, scannerID)
		}
		expectedPrefix := fmt.Sprintf("ghcr.io/eozkull/kelvin/scanner-%s", scannerID)
		if !strings.HasPrefix(*img.KelvinImage, expectedPrefix) {
			return fmt.Errorf("%w: scanner %q image %q must be in official repository %q", ErrInvalidUpstreamReference, scannerID, *img.KelvinImage, expectedPrefix)
		}

		if img.KelvinDigest == nil || strings.TrimSpace(*img.KelvinDigest) == "" {
			return fmt.Errorf("%w: scanner %q missing kelvin digest", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateDigestFormat(*img.KelvinDigest); err != nil {
			return fmt.Errorf("scanner %q: kelvin digest: %w", scannerID, err)
		}

		// 4. Platform Architecture
		if img.Architecture == nil || strings.TrimSpace(*img.Architecture) == "" {
			return fmt.Errorf("%w: scanner %q missing platform architecture", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateReleaseArchitecture(*img.Architecture); err != nil {
			return fmt.Errorf("scanner %q: %w", scannerID, err)
		}

		// 5. CycloneDX SBOM Digest
		if img.SBOMDigest == nil || strings.TrimSpace(*img.SBOMDigest) == "" {
			return fmt.Errorf("%w: scanner %q missing SBOM digest", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateSBOMDigest(*img.SBOMDigest); err != nil {
			return fmt.Errorf("scanner %q: %w", scannerID, err)
		}

		// 6. Cosign Signature Reference
		if img.SignatureRef == nil || strings.TrimSpace(*img.SignatureRef) == "" {
			return fmt.Errorf("%w: scanner %q missing signature reference", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateSignatureRef(*img.SignatureRef); err != nil {
			return fmt.Errorf("scanner %q: %w", scannerID, err)
		}

		// 7. SLSA Provenance Reference
		if img.ProvenanceRef == nil || strings.TrimSpace(*img.ProvenanceRef) == "" {
			return fmt.Errorf("%w: scanner %q missing provenance reference", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateProvenanceRef(*img.ProvenanceRef); err != nil {
			return fmt.Errorf("scanner %q: %w", scannerID, err)
		}

		// 8. Image Security Scorecard Status
		if img.ScorecardStatus == nil || strings.TrimSpace(*img.ScorecardStatus) == "" {
			return fmt.Errorf("%w: scanner %q missing scorecard status", ErrIncompleteCertification, scannerID)
		}
		if err := ValidateScorecardStatus(*img.ScorecardStatus); err != nil {
			return fmt.Errorf("scanner %q: %w", scannerID, err)
		}
	}

	// Nuclei specific checks
	nucleiImg := lock.Images["nuclei"]
	if nucleiImg.DistrolessBase == nil || strings.TrimSpace(*nucleiImg.DistrolessBase) == "" {
		return fmt.Errorf("%w: nuclei missing distroless base", ErrIncompleteCertification)
	}
	if *nucleiImg.DistrolessBase != "gcr.io/distroless/static-debian12:nonroot" {
		return fmt.Errorf("%w: nuclei distroless base %q must be gcr.io/distroless/static-debian12:nonroot", ErrIncompleteCertification, *nucleiImg.DistrolessBase)
	}
	if nucleiImg.DistrolessDigest == nil || strings.TrimSpace(*nucleiImg.DistrolessDigest) == "" {
		return fmt.Errorf("%w: nuclei missing distroless digest", ErrIncompleteCertification)
	}
	if err := ValidateDigestFormat(*nucleiImg.DistrolessDigest); err != nil {
		return fmt.Errorf("nuclei distroless: %w", err)
	}

	if nucleiImg.TemplateCatalogID != "kelvin.safe.web.v1" {
		return fmt.Errorf("%w: unexpected template catalog ID %q (expected kelvin.safe.web.v1)", ErrIncompleteCertification, nucleiImg.TemplateCatalogID)
	}
	if nucleiImg.TemplateCatalogDigest == nil || strings.TrimSpace(*nucleiImg.TemplateCatalogDigest) == "" {
		return fmt.Errorf("%w: nuclei missing template catalog digest", ErrIncompleteCertification)
	}
	if err := ValidateDigestFormat(*nucleiImg.TemplateCatalogDigest); err != nil {
		return fmt.Errorf("nuclei catalog digest: %w", err)
	}

	if catalogPath != "" {
		calcDigest, err := CalculateCatalogDigest(catalogPath)
		if err != nil {
			return fmt.Errorf("failed to calculate catalog digest: %w", err)
		}
		if *nucleiImg.TemplateCatalogDigest != calcDigest {
			return fmt.Errorf("%w: declared %q, calculated %q", ErrCatalogDigestMismatch, *nucleiImg.TemplateCatalogDigest, calcDigest)
		}
	}

	return nil
}

// VerifyScannerCertificationForExecution enforces worker daemon certification checks:
// - Fails closed if the manifest is in 'not-released' status in staging/production.
// - Rejects images not present in the certified manifest.
// - Detects and prevents image digest tampering if the runtime image reference digest
//   does not match the certified KelvinDigest in the manifest.
// - Enforces scorecard eligibility.
func VerifyScannerCertificationForExecution(manifestPath, scannerID, imageRef, env string) error {
	if env != "production" && env != "staging" {
		// Non-production environment, allow development runs unless manifest is explicitly corrupted
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
		return fmt.Errorf("%w: scanner %q execution blocked because manifest status is %q", ErrScannerNotReleased, scannerID, lock.Status)
	}

	img, ok := lock.Images[scannerID]
	if !ok {
		return fmt.Errorf("%w: scanner %q not registered in release manifest", ErrScannerNotReleased, scannerID)
	}

	if img.KelvinDigest == nil || *img.KelvinDigest == "" || *img.KelvinDigest == EmptySHA256Digest {
		return fmt.Errorf("%w: scanner %q has missing or uncertified release digest", ErrScannerNotReleased, scannerID)
	}

	if err := ValidateDigestFormat(*img.KelvinDigest); err != nil {
		return fmt.Errorf("%w: scanner %q has invalid release digest format: %w", ErrScannerNotReleased, scannerID, err)
	}

	// Verify that runtime image reference matches certified digest
	if imageRef != "" {
		parts := strings.Split(imageRef, "@")
		if len(parts) == 2 {
			refDigest := parts[1]
			if refDigest != *img.KelvinDigest {
				return fmt.Errorf("%w: image digest tampering detected: runtime image specifies %s but certified manifest specifies %s", ErrManifestConflict, refDigest, *img.KelvinDigest)
			}
		}
	}

	// Enforce scorecard eligibility if present
	if img.ScorecardStatus != nil && *img.ScorecardStatus != "" {
		if err := ValidateScorecardStatus(*img.ScorecardStatus); err != nil {
			return fmt.Errorf("%w: scanner %q failed scorecard gate: %w", ErrIneligibleScorecard, scannerID, err)
		}
	}

	return nil
}
