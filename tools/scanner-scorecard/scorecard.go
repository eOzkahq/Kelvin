package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	sha256DigestRegex = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type ScorecardInput struct {
	ScannerName     string            `json:"scanner_name"`
	ImageRef        string            `json:"image_ref"`
	ImageDigest     string            `json:"image_digest"`
	Architecture    string            `json:"architecture"`
	RuntimeUser     string            `json:"runtime_user"`
	PackageCount    int               `json:"package_count"`
	SBOMPresent     bool              `json:"sbom_present"`
	SBOMFormat      string            `json:"sbom_format"`
	VulnCounts      VulnerabilityCount`json:"vuln_counts"`
	WaiverCounts    WaiverCount       `json:"waiver_counts"`
	SourceCommit    string            `json:"source_commit"`
	BuilderDigest   string            `json:"builder_digest"`
	BuildTimestamp  string            `json:"build_timestamp"`
}

type VulnerabilityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type WaiverCount struct {
	Approved  int `json:"approved"`
	Pending   int `json:"pending"`
	Expired   int `json:"expired"`
	Unhandled int `json:"unhandled"`
}

type SecurityScorecard struct {
	SchemaVersion      string            `json:"schema_version"`
	EvaluatedAt        string            `json:"evaluated_at"`
	Scanner            string            `json:"scanner"`
	ImageDigest        string            `json:"image_digest"`
	Architecture       string            `json:"architecture"`
	RuntimeIdentity    string            `json:"runtime_identity"`
	PackageCount       int               `json:"package_count"`
	SBOMStatus         string            `json:"sbom_status"`
	Vulnerabilities    VulnerabilityCount`json:"vulnerabilities"`
	Waivers            WaiverCount       `json:"waivers"`
	Provenance         BuildProvenance   `json:"provenance"`
	ReleaseEligibility string            `json:"release_eligibility"` // ELIGIBLE or INELIGIBLE
	BlockingReasons    []string          `json:"blocking_reasons,omitempty"`
}

type BuildProvenance struct {
	SourceCommit   string `json:"source_commit"`
	BuilderDigest  string `json:"builder_digest"`
	BuildTimestamp string `json:"build_timestamp"`
}

// Evaluate computes the security scorecard and release eligibility from build evidence.
func Evaluate(input ScorecardInput) *SecurityScorecard {
	sc := &SecurityScorecard{
		SchemaVersion:      "1.0.0",
		EvaluatedAt:        time.Now().UTC().Format(time.RFC3339),
		Scanner:            input.ScannerName,
		ImageDigest:        input.ImageDigest,
		Architecture:       input.Architecture,
		RuntimeIdentity:    input.RuntimeUser,
		PackageCount:       input.PackageCount,
		SBOMStatus:         "MISSING",
		Vulnerabilities:    input.VulnCounts,
		Waivers:            input.WaiverCounts,
		Provenance: BuildProvenance{
			SourceCommit:   input.SourceCommit,
			BuilderDigest:  input.BuilderDigest,
			BuildTimestamp: input.BuildTimestamp,
		},
		BlockingReasons: make([]string, 0),
	}

	// 1. Verify Image Digest
	if !sha256DigestRegex.MatchString(input.ImageDigest) {
		sc.BlockingReasons = append(sc.BlockingReasons, fmt.Sprintf("Invalid or missing immutable image digest: %q", input.ImageDigest))
	}

	// 2. Verify Architecture
	if input.Architecture != "linux/arm64" && input.Architecture != "linux/amd64" {
		sc.BlockingReasons = append(sc.BlockingReasons, fmt.Sprintf("Unsupported target architecture: %q (must be linux/arm64 or linux/amd64)", input.Architecture))
	}

	// 3. Verify Runtime User Identity
	if input.RuntimeUser != "10001:10001" {
		sc.BlockingReasons = append(sc.BlockingReasons, fmt.Sprintf("Non-compliant runtime user: %q (must enforce 10001:10001)", input.RuntimeUser))
	}

	// 4. Verify SBOM
	if input.SBOMPresent {
		sc.SBOMStatus = fmt.Sprintf("VERIFIED (%s)", input.SBOMFormat)
	} else {
		sc.BlockingReasons = append(sc.BlockingReasons, "CycloneDX SBOM missing or malformed")
	}

	// 5. Verify Vulnerability & Waiver Governance
	if input.WaiverCounts.Unhandled > 0 {
		sc.BlockingReasons = append(sc.BlockingReasons, fmt.Sprintf("%d unhandled vulnerability finding(s) detected", input.WaiverCounts.Unhandled))
	}
	if input.WaiverCounts.Expired > 0 {
		sc.BlockingReasons = append(sc.BlockingReasons, fmt.Sprintf("%d expired waiver(s) detected", input.WaiverCounts.Expired))
	}
	if input.WaiverCounts.Pending > 0 {
		sc.BlockingReasons = append(sc.BlockingReasons, fmt.Sprintf("%d unreviewed pending waiver(s) detected", input.WaiverCounts.Pending))
	}

	// 6. Verify Provenance Evidence
	if input.SourceCommit == "" {
		sc.BlockingReasons = append(sc.BlockingReasons, "Missing source git commit in build provenance")
	}
	if input.BuilderDigest == "" || !sha256DigestRegex.MatchString(input.BuilderDigest) {
		sc.BlockingReasons = append(sc.BlockingReasons, "Missing or invalid builder digest in build provenance")
	}

	if len(sc.BlockingReasons) == 0 {
		sc.ReleaseEligibility = "ELIGIBLE"
	} else {
		sc.ReleaseEligibility = "INELIGIBLE"
	}

	return sc
}

func (sc *SecurityScorecard) ToJSON() ([]byte, error) {
	return json.MarshalIndent(sc, "", "  ")
}

func (sc *SecurityScorecard) ToMarkdown() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## 🛡️ Kelvin Scanner Security Scorecard: %s\n\n", strings.ToUpper(sc.Scanner)))
	b.WriteString(fmt.Sprintf("- **Release Eligibility:** `%s`\n", sc.ReleaseEligibility))
	b.WriteString(fmt.Sprintf("- **Evaluated At:** `%s`\n", sc.EvaluatedAt))
	b.WriteString(fmt.Sprintf("- **Image Digest:** `%s`\n", sc.ImageDigest))
	b.WriteString(fmt.Sprintf("- **Architecture:** `%s`\n", sc.Architecture))
	b.WriteString(fmt.Sprintf("- **Runtime Identity:** `%s`\n", sc.RuntimeIdentity))
	b.WriteString(fmt.Sprintf("- **Installed Packages:** `%d`\n", sc.PackageCount))
	b.WriteString(fmt.Sprintf("- **SBOM Status:** `%s`\n", sc.SBOMStatus))
	b.WriteString("\n### 🔍 Vulnerability & Waiver Breakdown\n\n")
	b.WriteString("| Metric | Count |\n| :--- | :---: |\n")
	b.WriteString(fmt.Sprintf("| Critical CVEs | %d |\n", sc.Vulnerabilities.Critical))
	b.WriteString(fmt.Sprintf("| High CVEs | %d |\n", sc.Vulnerabilities.High))
	b.WriteString(fmt.Sprintf("| Approved Waivers (Active) | %d |\n", sc.Waivers.Approved))
	b.WriteString(fmt.Sprintf("| Pending Waivers (Gated) | %d |\n", sc.Waivers.Pending))
	b.WriteString(fmt.Sprintf("| Expired Waivers (Gated) | %d |\n", sc.Waivers.Expired))
	b.WriteString(fmt.Sprintf("| Unhandled Findings (Gated) | %d |\n", sc.Waivers.Unhandled))

	b.WriteString("\n### 📦 Build Provenance\n\n")
	b.WriteString(fmt.Sprintf("- **Source Commit:** `%s`\n", sc.Provenance.SourceCommit))
	b.WriteString(fmt.Sprintf("- **Builder Digest:** `%s`\n", sc.Provenance.BuilderDigest))
	b.WriteString(fmt.Sprintf("- **Build Timestamp:** `%s`\n", sc.Provenance.BuildTimestamp))

	if len(sc.BlockingReasons) > 0 {
		b.WriteString("\n### 🚫 Blocking Reasons (Fail-Closed)\n\n")
		for _, r := range sc.BlockingReasons {
			b.WriteString(fmt.Sprintf("- ❌ %s\n", r))
		}
	} else {
		b.WriteString("\n### ✅ Security Verification Passed\nAll security invariants, non-root contracts, SBOM schemas, and waiver requirements are satisfied.\n")
	}

	return b.String()
}
