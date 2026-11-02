package findings

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// InterpretationRuleVersion defines the active normative version for severity and confidence interpretation rules.
const InterpretationRuleVersion = "kelvin.interpretation.v1"

// Canonical Severity constants adhering to finding.v1.json.
const (
	CanonicalSeverityCritical      = "CRITICAL"
	CanonicalSeverityHigh          = "HIGH"
	CanonicalSeverityMedium        = "MEDIUM"
	CanonicalSeverityLow           = "LOW"
	CanonicalSeverityInformational = "INFORMATIONAL"
)

// Canonical Confidence Bands representing evidence strength and proof quality.
const (
	ConfidenceBandCertain     = "CERTAIN"     // [0.90, 1.00] - Deterministic check or concrete proof of exploitability
	ConfidenceBandFirm        = "FIRM"        // [0.70, 0.89] - Strong heuristic with active verification
	ConfidenceBandTentative   = "TENTATIVE"   // [0.40, 0.69] - Heuristic or indirect indicator requiring human review
	ConfidenceBandUnconfirmed = "UNCONFIRMED" // [0.00, 0.39] - Speculative or low-reliability signal
	ConfidenceBandUnspecified = "UNSPECIFIED" // Omitted or unsupported by scanner
)

// FindingClassification preserves original scanner classifications while providing canonicalized interpretation.
type FindingClassification struct {
	RuleVersion           string   `json:"rule_version"`
	ScannerName           string   `json:"scanner_name"`
	OriginalSeverity      string   `json:"original_severity"`
	OriginalConfidence    string   `json:"original_confidence,omitempty"`
	CanonicalSeverity     string   `json:"canonical_severity"`
	CanonicalConfidence   float64  `json:"canonical_confidence"`
	ConfidenceBand        string   `json:"confidence_band"`
	ConfidenceUnspecified bool     `json:"confidence_unspecified"`
	CVSSScore             *float64 `json:"cvss_score,omitempty"`
	DimensionsDistinct    bool     `json:"dimensions_distinct"`
	Explanation           string   `json:"explanation"`
}

// MapConfidenceBand classifies a numeric confidence score [0.0, 1.0] into a canonical operational band.
func MapConfidenceBand(confidence float64, unspecified bool) string {
	if unspecified {
		return ConfidenceBandUnspecified
	}
	switch {
	case confidence >= 0.90:
		return ConfidenceBandCertain
	case confidence >= 0.70:
		return ConfidenceBandFirm
	case confidence >= 0.40:
		return ConfidenceBandTentative
	default:
		return ConfidenceBandUnconfirmed
	}
}

// ComputeConfidenceAttenuation calculates the risk multiplier factor for a given confidence.
// The formula is bounded: Factor = 0.5 + (Confidence * 0.5), yielding [0.50, 1.00].
// This guarantees that low confidence never zeroes out or dangerously conceals high-severity findings.
func ComputeConfidenceAttenuation(confidence float64) float64 {
	if confidence < 0.0 {
		confidence = 0.0
	} else if confidence > 1.0 {
		confidence = 1.0
	}
	raw := 0.5 + (confidence * 0.5)
	return math.Round(raw*100) / 100
}

// InterpretFinding processes raw scanner inputs to produce a verified, canonicalized finding classification.
// It maintains original scanner classifications while ensuring that severity (impact potential)
// and confidence (proof quality) remain strictly orthogonal dimensions.
func InterpretFinding(
	scannerName, rawSeverity, rawConfidence string,
	cvssScore *float64,
) FindingClassification {
	scannerLower := strings.ToLower(strings.TrimSpace(scannerName))
	origSev := strings.TrimSpace(rawSeverity)
	origConf := strings.TrimSpace(rawConfidence)

	var canonicalSev string
	var canonicalConf float64
	var unspecifiedConf bool

	// 1. Scanner-Specific Interpretation
	switch {
	case strings.Contains(scannerLower, "zap"):
		canonicalSev, canonicalConf, unspecifiedConf = interpretZAP(origSev, origConf)

	case strings.Contains(scannerLower, "nuclei"):
		canonicalSev, canonicalConf, unspecifiedConf = interpretNuclei(origSev, origConf)

	case strings.Contains(scannerLower, "tls") || strings.Contains(scannerLower, "http") || strings.Contains(scannerLower, "builtin"):
		canonicalSev, canonicalConf, unspecifiedConf = interpretBuiltin(origSev, origConf)

	default:
		canonicalSev, canonicalConf, unspecifiedConf = interpretGeneric(origSev, origConf)
	}

	// 2. Authoritative CVSS Override: When an authoritative CVSS score is present and valid,
	// it supersedes scanner severity to provide standard baseline comparability.
	if cvssScore != nil && *cvssScore >= 0.0 && *cvssScore <= 10.0 {
		canonicalSev = MapCVSSScoreToSeverity(*cvssScore)
	}

	// 3. Resolve Canonical Confidence Band
	confBand := MapConfidenceBand(canonicalConf, unspecifiedConf)

	// 4. Invariant: Orthogonal Dimensions
	// Severity (impact magnitude) and confidence (evidence certainty) are strictly distinct.
	dimensionsDistinct := true

	explanation := fmt.Sprintf(
		"Rule %s: %s [%s/%s] -> Canonical [%s / %s (%.2f)] (Attenuation: %.2f)",
		InterpretationRuleVersion,
		scannerName,
		origSev,
		origConf,
		canonicalSev,
		confBand,
		canonicalConf,
		ComputeConfidenceAttenuation(canonicalConf),
	)

	return FindingClassification{
		RuleVersion:           InterpretationRuleVersion,
		ScannerName:           scannerName,
		OriginalSeverity:      origSev,
		OriginalConfidence:    origConf,
		CanonicalSeverity:     canonicalSev,
		CanonicalConfidence:   canonicalConf,
		ConfidenceBand:        confBand,
		ConfidenceUnspecified: unspecifiedConf,
		CVSSScore:             cvssScore,
		DimensionsDistinct:    dimensionsDistinct,
		Explanation:           explanation,
	}
}

// interpretZAP translates OWASP ZAP numeric/text risk codes and confidence levels.
func interpretZAP(rawSev, rawConf string) (string, float64, bool) {
	var sev string
	normSev := strings.ToLower(rawSev)
	switch normSev {
	case "3", "high":
		sev = CanonicalSeverityHigh
	case "2", "medium":
		sev = CanonicalSeverityMedium
	case "1", "low":
		sev = CanonicalSeverityLow
	case "0", "informational", "info":
		sev = CanonicalSeverityInformational
	default:
		sev = CanonicalSeverityInformational
	}

	var conf float64
	var unspecified bool
	normConf := strings.ToLower(rawConf)
	switch normConf {
	case "3", "high", "certain":
		conf = 0.90
	case "2", "medium", "firm":
		conf = 0.70
	case "1", "low", "tentative":
		conf = 0.50
	case "0", "false positive":
		conf = 0.20
	case "4", "user confirmed":
		conf = 1.00
	case "":
		conf = 0.70 // Conservative default
		unspecified = true
	default:
		conf = 0.70
		unspecified = true
	}

	return sev, conf, unspecified
}

// interpretNuclei translates ProjectDiscovery Nuclei severity levels.
func interpretNuclei(rawSev, rawConf string) (string, float64, bool) {
	var sev string
	normSev := strings.ToLower(rawSev)
	switch normSev {
	case "critical":
		sev = CanonicalSeverityCritical
	case "high":
		sev = CanonicalSeverityHigh
	case "medium":
		sev = CanonicalSeverityMedium
	case "low":
		sev = CanonicalSeverityLow
	case "info":
		sev = CanonicalSeverityInformational
	default:
		sev = CanonicalSeverityInformational
	}

	var conf float64
	var unspecified bool
	if parsed, err := strconv.ParseFloat(rawConf, 64); err == nil && parsed >= 0.0 && parsed <= 1.0 {
		conf = parsed
	} else if rawConf != "" {
		switch strings.ToLower(rawConf) {
		case "certain", "high":
			conf = 0.95
		case "firm", "medium":
			conf = 0.75
		case "tentative", "low":
			conf = 0.50
		default:
			conf = 0.95
			unspecified = true
		}
	} else {
		// Nuclei template matches are signature-verified, defaulting to high confidence
		conf = 0.95
		unspecified = false
	}

	return sev, conf, unspecified
}

// interpretBuiltin translates internal HTTP and TLS result checks.
func interpretBuiltin(rawSev, rawConf string) (string, float64, bool) {
	var sev string
	normSev := strings.ToUpper(rawSev)
	switch normSev {
	case "CRITICAL":
		sev = CanonicalSeverityCritical
	case "HIGH":
		sev = CanonicalSeverityHigh
	case "MEDIUM":
		sev = CanonicalSeverityMedium
	case "LOW":
		sev = CanonicalSeverityLow
	case "INFO", "INFORMATIONAL":
		sev = CanonicalSeverityInformational
	default:
		sev = CanonicalSeverityInformational
	}

	// Built-in deterministic tests have full proof confidence
	return sev, 1.00, false
}

// interpretGeneric translates unknown or generic scanner outputs safely.
func interpretGeneric(rawSev, rawConf string) (string, float64, bool) {
	var sev string
	normSev := strings.ToUpper(rawSev)
	switch normSev {
	case "CRITICAL":
		sev = CanonicalSeverityCritical
	case "HIGH":
		sev = CanonicalSeverityHigh
	case "MEDIUM":
		sev = CanonicalSeverityMedium
	case "LOW":
		sev = CanonicalSeverityLow
	case "INFO", "INFORMATIONAL":
		sev = CanonicalSeverityInformational
	default:
		sev = CanonicalSeverityMedium
	}

	var conf float64
	var unspecified bool
	if parsed, err := strconv.ParseFloat(rawConf, 64); err == nil && parsed >= 0.0 && parsed <= 1.0 {
		conf = parsed
	} else {
		conf = 0.80
		unspecified = true
	}

	return sev, conf, unspecified
}

// MapCVSSScoreToSeverity maps a standard CVSS score (0.0 to 10.0) into its canonical severity band.
func MapCVSSScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return CanonicalSeverityCritical
	case score >= 7.0:
		return CanonicalSeverityHigh
	case score >= 4.0:
		return CanonicalSeverityMedium
	case score > 0.0:
		return CanonicalSeverityLow
	default:
		return CanonicalSeverityInformational
	}
}
