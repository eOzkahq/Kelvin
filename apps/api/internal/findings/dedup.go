package findings

import (
	"fmt"
	"sort"

	"github.com/kelvin/kelvin/packages/common/normalization"
)

// DeduplicationAction indicates how an in-assessment observation was handled.
type DeduplicationAction string

const (
	ActionCreateDistinct      DeduplicationAction = "CREATE_DISTINCT"
	ActionMergeSameAssessment DeduplicationAction = "MERGE_SAME_ASSESSMENT"
	ActionReplayIdentical     DeduplicationAction = "REPLAY_IDENTICAL"
)

// DeduplicationDecision logs the rationale for merging or distinguishing findings.
type DeduplicationDecision struct {
	Fingerprint       string              `json:"fingerprint"`
	Action            DeduplicationAction `json:"action"`
	PrimaryScanner    string              `json:"primary_scanner"`
	SecondaryScanners []string            `json:"secondary_scanners,omitempty"`
	EvidenceCount     int                 `json:"evidence_count"`
	TargetEndpoint    string              `json:"target_endpoint"`
	Reason            string              `json:"reason"`
}

// InAssessmentDeduplicator groups and aggregates same-assessment findings deterministically.
type InAssessmentDeduplicator struct{}

// NewInAssessmentDeduplicator creates a new in-assessment deduplication engine.
func NewInAssessmentDeduplicator() *InAssessmentDeduplicator {
	return &InAssessmentDeduplicator{}
}

// Deduplicate evaluates a slice of canonical findings from the same assessment,
// merging identical findings by deterministic fingerprint while aggregating evidence
// and preserving multi-scanner provenance. Distinct findings with different locations
// or vulnerability signatures are never merged.
func (d *InAssessmentDeduplicator) Deduplicate(
	findings []normalization.CanonicalFinding,
) ([]normalization.CanonicalFinding, []DeduplicationDecision, error) {
	if len(findings) == 0 {
		return []normalization.CanonicalFinding{}, []DeduplicationDecision{}, nil
	}

	type findingGroup struct {
		canonical normalization.CanonicalFinding
		scanners  []string
		decision  DeduplicationDecision
	}

	groups := make(map[string]*findingGroup)
	var orderedFingerprints []string

	for _, f := range findings {
		fpResult, err := normalization.GenerateFingerprint(normalization.FingerprintInput{
			Asset:      f.Target.Asset,
			Endpoint:   f.Target.Endpoint,
			TemplateID: f.Vulnerability.TemplateID,
			CVEIDs:     f.Vulnerability.CVEIDs,
			CWEID:      f.Vulnerability.CWEID,
			Title:      f.Title,
			Algorithm:  normalization.AlgorithmV1,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("dedup: generate fingerprint failed: %w", err)
		}
		fp := fpResult.Digest

		group, exists := groups[fp]
		if !exists {
			// First occurrence of this fingerprint in this assessment
			scanners := []string{f.Scanner.Name}
			groups[fp] = &findingGroup{
				canonical: f,
				scanners:  scanners,
				decision: DeduplicationDecision{
					Fingerprint:    fp,
					Action:         ActionCreateDistinct,
					PrimaryScanner: f.Scanner.Name,
					EvidenceCount:  len(f.Evidence),
					TargetEndpoint: f.Target.Endpoint,
					Reason:         "First occurrence of deterministic fingerprint in assessment",
				},
			}
			orderedFingerprints = append(orderedFingerprints, fp)
		} else {
			// Duplicate occurrence of this fingerprint in the same assessment
			// Aggregate secondary evidence references without discarding distinct data
			group.canonical.Evidence = mergeEvidence(group.canonical.Evidence, f.Evidence)

			// Aggregate tags
			group.canonical.Tags = mergeTags(group.canonical.Tags, f.Tags)

			// Preserve multi-scanner provenance
			hasScanner := false
			for _, s := range group.scanners {
				if s == f.Scanner.Name {
					hasScanner = true
					break
				}
			}
			if !hasScanner {
				group.scanners = append(group.scanners, f.Scanner.Name)
			}

			// Preserve scanner metadata
			if group.canonical.ScannerMeta == nil {
				group.canonical.ScannerMeta = make(map[string]any)
			}
			group.canonical.ScannerMeta["secondary_scanners"] = group.scanners
			if f.ScannerMeta != nil {
				group.canonical.ScannerMeta["provenance_"+f.Scanner.Name] = f.ScannerMeta
			}

			// Update decision log
			group.decision.Action = ActionMergeSameAssessment
			group.decision.SecondaryScanners = group.scanners[1:]
			group.decision.EvidenceCount = len(group.canonical.Evidence)
			group.decision.Reason = "Matching fingerprint in same assessment; aggregated secondary evidence and preserved scanner source provenance"
		}
	}

	// Deterministic sorting of results by fingerprint
	sort.Strings(orderedFingerprints)

	result := make([]normalization.CanonicalFinding, 0, len(orderedFingerprints))
	decisions := make([]DeduplicationDecision, 0, len(orderedFingerprints))

	for _, fp := range orderedFingerprints {
		grp := groups[fp]
		result = append(result, grp.canonical)
		decisions = append(decisions, grp.decision)
	}

	return result, decisions, nil
}

// mergeEvidence combines evidence slices without duplicating identical payloads or snippets.
func mergeEvidence(existing, additional []normalization.Evidence) []normalization.Evidence {
	if len(additional) == 0 {
		return existing
	}
	merged := make([]normalization.Evidence, len(existing))
	copy(merged, existing)

	for _, add := range additional {
		isDuplicate := false
		for _, ex := range existing {
			if ex.ChecksumSHA256 != "" && ex.ChecksumSHA256 == add.ChecksumSHA256 {
				isDuplicate = true
				break
			}
			if ex.ContentRedacted != "" && ex.ContentRedacted == add.ContentRedacted {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			merged = append(merged, add)
		}
	}
	return merged
}

// mergeTags unions two string slices deterministically without duplicates.
func mergeTags(existing, additional []string) []string {
	seen := make(map[string]bool)
	var merged []string
	for _, t := range existing {
		if !seen[t] && t != "" {
			seen[t] = true
			merged = append(merged, t)
		}
	}
	for _, t := range additional {
		if !seen[t] && t != "" {
			seen[t] = true
			merged = append(merged, t)
		}
	}
	sort.Strings(merged)
	return merged
}
