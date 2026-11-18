package normalization

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

const (
	// MaxEvidenceBytesPerFinding enforces the 64KiB ceiling on inline evidence previews (FINDING_SCHEMA.md §6.1).
	MaxEvidenceBytesPerFinding = 65536
)

var allowedEvidenceTypes = map[string]bool{
	"HTTP_EXCHANGE": true,
	"HEADER_DUMP":   true,
	"SCREENSHOT":    true,
	"FILE":          true,
	"LOG":           true,
}

var allowedSeverities = map[string]bool{
	SeverityCritical:      true,
	SeverityHigh:          true,
	SeverityMedium:        true,
	SeverityLow:           true,
	SeverityInformational: true,
}

// QuarantineRecord captures details of a rejected or quarantined finding.
type QuarantineRecord struct {
	Index      int       `json:"index"`
	Reason     string    `json:"reason"`
	Violations []string  `json:"violations"`
	RawSnippet string    `json:"raw_snippet,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}

// ValidationReport provides observable metrics and status on normalized batch validation.
type ValidationReport struct {
	TotalProcessed int                `json:"total_processed"`
	AcceptedCount  int                `json:"accepted_count"`
	RejectedCount  int                `json:"rejected_count"`
	DuplicateCount int                `json:"duplicate_count"`
	Accepted       []CanonicalFinding `json:"accepted"`
	Quarantined    []QuarantineRecord `json:"quarantined"`
}

// ResultValidator validates normalized findings against data quality, completeness, and schema rules.
type ResultValidator struct {
	allowIncomplete bool
}

// NewResultValidator creates a new finding validation gate.
func NewResultValidator() *ResultValidator {
	return &ResultValidator{}
}

// ValidateSingle inspects an individual canonical finding, returning all validation errors observed.
func (v *ResultValidator) ValidateSingle(f CanonicalFinding, expectedAsset string) []string {
	var violations []string

	// 1. Schema version
	if f.SchemaVersion != "1.0" {
		violations = append(violations, fmt.Sprintf("invalid schema_version %q: must be 1.0", f.SchemaVersion))
	}

	// 2. Title bounds
	if strings.TrimSpace(f.Title) == "" {
		violations = append(violations, "title is empty")
	} else if len(f.Title) > 500 {
		violations = append(violations, fmt.Sprintf("title length %d exceeds 500 characters", len(f.Title)))
	}

	// 3. Severity enum
	if !allowedSeverities[f.Severity] {
		violations = append(violations, fmt.Sprintf("unsupported severity enum %q", f.Severity))
	}

	// 4. Confidence range
	if f.Confidence < 0.0 || f.Confidence > 1.0 {
		violations = append(violations, fmt.Sprintf("confidence %f out of range [0.0, 1.0]", f.Confidence))
	}

	// 5. Target integrity
	if strings.TrimSpace(f.Target.Asset) == "" {
		violations = append(violations, "target asset is missing")
	} else if expectedAsset != "" {
		normExpected := NormalizeAsset(expectedAsset)
		normTarget := NormalizeAsset(f.Target.Asset)
		if normTarget != normExpected && !strings.HasSuffix(normTarget, "."+normExpected) {
			violations = append(violations, fmt.Sprintf("target asset %q does not match expected assessment asset %q", normTarget, normExpected))
		}
	}

	if f.Target.Endpoint != "" {
		if strings.ContainsAny(f.Target.Endpoint, "?#") {
			violations = append(violations, "target endpoint must not contain query parameters or fragments")
		}
	}

	// 6. Vulnerability key and fingerprint integrity
	recomputedFP, _, err := ComputeFingerprint(
		f.Target.Asset,
		f.Target.Endpoint,
		f.Vulnerability.TemplateID,
		f.Vulnerability.CVEIDs,
		f.Vulnerability.CWEID,
		f.Title,
	)
	claimedFP := f.Fingerprint
	if strings.HasPrefix(claimedFP, "fp_") {
		if _, digest, parseErr := ParseTaggedFingerprint(claimedFP); parseErr == nil {
			claimedFP = digest
		}
	}
	if err != nil {
		violations = append(violations, fmt.Sprintf("fingerprint recomputation failed: %v", err))
	} else if f.Fingerprint != "" && claimedFP != recomputedFP {
		violations = append(violations, fmt.Sprintf("fingerprint mismatch: claimed %q, computed %q", f.Fingerprint, recomputedFP))
	}

	// 7. Evidence validation
	totalEvidenceSize := 0
	for i, ev := range f.Evidence {
		if !allowedEvidenceTypes[ev.Type] {
			violations = append(violations, fmt.Sprintf("evidence[%d]: invalid type %q", i, ev.Type))
		}
		if ev.RedactedFields == nil {
			violations = append(violations, fmt.Sprintf("evidence[%d]: redacted_fields attestation array is required", i))
		}
		evLen := len(ev.ContentRedacted)
		totalEvidenceSize += evLen
		if evLen > MaxEvidenceBytesPerFinding {
			violations = append(violations, fmt.Sprintf("evidence[%d]: inline content size %d exceeds 64KiB cap", i, evLen))
		}
	}

	// 8. Scanner provenance
	if strings.TrimSpace(f.Scanner.Name) == "" {
		violations = append(violations, "scanner name is missing")
	}
	if strings.TrimSpace(f.Scanner.AdapterVersion) == "" {
		violations = append(violations, "scanner adapter_version is missing")
	}

	// 9. Discovery timestamp
	if strings.TrimSpace(f.DiscoveredAt) == "" {
		violations = append(violations, "discovered_at timestamp is missing")
	}

	return violations
}

// ValidateBatch validates, deduplicates, and filters a batch of findings, returning an observable report.
func (v *ResultValidator) ValidateBatch(rawFindings []json.RawMessage, expectedAsset string) ValidationReport {
	report := ValidationReport{
		TotalProcessed: len(rawFindings),
		Accepted:       make([]CanonicalFinding, 0, len(rawFindings)),
		Quarantined:    make([]QuarantineRecord, 0),
	}

	seenFingerprints := make(map[string]bool)
	normalizer := NewNormalizer()

	for i, raw := range rawFindings {
		// Layer 1: Payload guard validation
		if err := parserguard.ValidatePayload(raw); err != nil {
			report.RejectedCount++
			snippet := string(raw)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			report.Quarantined = append(report.Quarantined, QuarantineRecord{
				Index:      i,
				Reason:     "payload guard violation",
				Violations: []string{err.Error()},
				RawSnippet: snippet,
				DetectedAt: time.Now().UTC(),
			})
			continue
		}

		// Layer 2: Structural adapter validation
		if err := adapters.ValidateFindings(raw); err != nil {
			report.RejectedCount++
			snippet := string(raw)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			report.Quarantined = append(report.Quarantined, QuarantineRecord{
				Index:      i,
				Reason:     "canonical schema validation failure",
				Violations: []string{err.Error()},
				RawSnippet: snippet,
				DetectedAt: time.Now().UTC(),
			})
			continue
		}

		// Layer 2.5: Check raw target endpoint for forbidden query/fragments
		var rawMap map[string]any
		if err := json.Unmarshal(raw, &rawMap); err == nil {
			if targetMap, ok := rawMap["target"].(map[string]any); ok {
				if ep, ok := targetMap["endpoint"].(string); ok && strings.ContainsAny(ep, "?#") {
					report.RejectedCount++
					snippet := string(raw)
					if len(snippet) > 200 {
						snippet = snippet[:200] + "..."
					}
					report.Quarantined = append(report.Quarantined, QuarantineRecord{
						Index:      i,
						Reason:     "endpoint format violation",
						Violations: []string{"target endpoint must not contain query parameters or fragments"},
						RawSnippet: snippet,
						DetectedAt: time.Now().UTC(),
					})
					continue
				}
			}

			// Layer 2.6: Check raw evidence size bounds
			if evList, ok := rawMap["evidence"].([]any); ok {
				hasHugeEvidence := false
				var hugeViolations []string
				for idx, evItem := range evList {
					if evMap, ok := evItem.(map[string]any); ok {
						if content, ok := evMap["content_redacted"].(string); ok && len(content) > MaxEvidenceBytesPerFinding {
							hasHugeEvidence = true
							hugeViolations = append(hugeViolations, fmt.Sprintf("evidence[%d]: inline content size %d exceeds 64KiB cap", idx, len(content)))
						}
					}
				}
				if hasHugeEvidence {
					report.RejectedCount++
					report.Quarantined = append(report.Quarantined, QuarantineRecord{
						Index:      i,
						Reason:     "evidence size violation",
						Violations: hugeViolations,
						DetectedAt: time.Now().UTC(),
					})
					continue
				}
			}
		}

		// Layer 3: Normalization & fingerprint derivation
		normFinding, err := normalizer.Normalize(raw, Context{})
		if err != nil {
			report.RejectedCount++
			report.Quarantined = append(report.Quarantined, QuarantineRecord{
				Index:      i,
				Reason:     "normalization error",
				Violations: []string{err.Error()},
				DetectedAt: time.Now().UTC(),
			})
			continue
		}

		// Layer 4: Deep completeness & quality validation
		violations := v.ValidateSingle(normFinding, expectedAsset)
		if len(violations) > 0 {
			report.RejectedCount++
			report.Quarantined = append(report.Quarantined, QuarantineRecord{
				Index:      i,
				Reason:     "completeness check failed",
				Violations: violations,
				DetectedAt: time.Now().UTC(),
			})
			continue
		}

		// Layer 5: In-batch deduplication (first occurrence wins with evidence & secondary scanner aggregation)
		if seenFingerprints[normFinding.Fingerprint] {
			report.DuplicateCount++
			for idx := range report.Accepted {
				if report.Accepted[idx].Fingerprint == normFinding.Fingerprint {
					report.Accepted[idx].Evidence = mergeWorkerEvidence(report.Accepted[idx].Evidence, normFinding.Evidence)
					if report.Accepted[idx].ScannerMeta == nil {
						report.Accepted[idx].ScannerMeta = make(map[string]any)
					}
					var secScanners []string
					if existingSec, ok := report.Accepted[idx].ScannerMeta["secondary_scanners"].([]string); ok {
						secScanners = existingSec
					} else {
						secScanners = []string{report.Accepted[idx].Scanner.Name}
					}
					hasScanner := false
					for _, s := range secScanners {
						if s == normFinding.Scanner.Name {
							hasScanner = true
							break
						}
					}
					if !hasScanner {
						secScanners = append(secScanners, normFinding.Scanner.Name)
					}
					report.Accepted[idx].ScannerMeta["secondary_scanners"] = secScanners
					break
				}
			}
			continue
		}
		seenFingerprints[normFinding.Fingerprint] = true

		report.Accepted = append(report.Accepted, normFinding)
		report.AcceptedCount++
	}

	return report
}

func mergeWorkerEvidence(existing, additional []Evidence) []Evidence {
	if len(additional) == 0 {
		return existing
	}
	merged := make([]Evidence, len(existing))
	copy(merged, existing)
	for _, add := range additional {
		isDup := false
		for _, ex := range existing {
			if ex.ChecksumSHA256 != "" && ex.ChecksumSHA256 == add.ChecksumSHA256 {
				isDup = true
				break
			}
			if ex.ContentRedacted != "" && ex.ContentRedacted == add.ContentRedacted {
				isDup = true
				break
			}
		}
		if !isDup {
			merged = append(merged, add)
		}
	}
	return merged
}
