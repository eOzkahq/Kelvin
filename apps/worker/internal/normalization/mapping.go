package normalization

import (
	"fmt"
	"strconv"
	"strings"
)

// SeverityMappingVersion defines the current normative version of severity and confidence translation rules.
const SeverityMappingVersion = "kelvin.severity_mapping.v1"

// Canonical Severity constants adhering to finding.v1.json.
const (
	SeverityCritical      = "CRITICAL"
	SeverityHigh          = "HIGH"
	SeverityMedium        = "MEDIUM"
	SeverityLow           = "LOW"
	SeverityInformational = "INFORMATIONAL"
)

// Confidence qualitative level identifiers.
const (
	ConfidenceLevelCertain   = "CERTAIN"
	ConfidenceLevelFirm      = "FIRM"
	ConfidenceLevelTentative = "TENTATIVE"
	ConfidenceLevelUnknown   = "UNKNOWN"
)

// MapCVSSScoreToSeverity resolves a CVSS v3.x/v4.0 score into a canonical severity band (FINDING_SCHEMA.md §4.2).
func MapCVSSScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0 && score <= 10.0:
		return SeverityCritical
	case score >= 7.0 && score < 9.0:
		return SeverityHigh
	case score >= 4.0 && score < 7.0:
		return SeverityMedium
	case score > 0.0 && score < 4.0:
		return SeverityLow
	default:
		return SeverityInformational
	}
}

// MapZAPSeverityAndConfidence converts ZAP numeric/string risk codes and confidence levels into canonical formats.
// Risk code: 0 -> INFORMATIONAL, 1 -> LOW, 2 -> MEDIUM, 3 -> HIGH.
func MapZAPSeverityAndConfidence(riskCode, zapConfidence string) (severity string, confidence float64, nativeSev, nativeConf string, err error) {
	trimmedRisk := strings.ToLower(strings.TrimSpace(riskCode))
	nativeSev = trimmedRisk
	nativeConf = strings.TrimSpace(zapConfidence)

	switch trimmedRisk {
	case "3", "high":
		severity = SeverityHigh
	case "2", "medium":
		severity = SeverityMedium
	case "1", "low":
		severity = SeverityLow
	case "0", "informational", "info":
		severity = SeverityInformational
	default:
		return "", 0, nativeSev, nativeConf, fmt.Errorf("mapping: unknown ZAP risk code %q", riskCode)
	}

	confidence = 0.5 // default calibrated baseline
	loweredConf := strings.ToLower(nativeConf)
	switch loweredConf {
	case "4", "confirmed", "certain":
		confidence = 1.0
	case "3", "high":
		confidence = 0.9
	case "2", "medium":
		confidence = 0.7
	case "1", "low":
		confidence = 0.5
	case "0", "false positive", "tentative":
		confidence = 0.2
	default:
		if num, err := strconv.ParseFloat(loweredConf, 64); err == nil && num >= 0.0 && num <= 1.0 {
			confidence = num
		}
	}

	return severity, confidence, nativeSev, nativeConf, nil
}

// MapNucleiSeverityAndConfidence converts Nuclei severity and optional CVSS score into canonical formats.
// Authoritative CVSS band takes precedence over native severity when present and divergent (FINDING_SCHEMA.md §4.2).
func MapNucleiSeverityAndConfidence(nucleiSeverity string, cvssScore float64) (severity string, confidence float64, nativeSev string, err error) {
	trimmed := strings.ToLower(strings.TrimSpace(nucleiSeverity))
	nativeSev = trimmed

	switch trimmed {
	case "critical":
		severity = SeverityCritical
		confidence = 0.95
	case "high":
		severity = SeverityHigh
		confidence = 0.85
	case "medium":
		severity = SeverityMedium
		confidence = 0.70
	case "low":
		severity = SeverityLow
		confidence = 0.60
	case "info", "informational":
		severity = SeverityInformational
		confidence = 0.50
	case "unknown", "":
		severity = SeverityInformational
		confidence = 0.50
	default:
		return "", 0, nativeSev, fmt.Errorf("mapping: unknown Nuclei severity %q", nucleiSeverity)
	}

	// If CVSS score is present, apply authoritative CVSS band (§4.2)
	if cvssScore > 0.0 && cvssScore <= 10.0 {
		cvssSev := MapCVSSScoreToSeverity(cvssScore)
		severity = cvssSev
	}

	return severity, confidence, nativeSev, nil
}

// ConfidenceFloatToLevel categorizes a normalized 0..1 confidence float into qualitative levels.
func ConfidenceFloatToLevel(score float64) string {
	switch {
	case score >= 0.95:
		return ConfidenceLevelCertain
	case score >= 0.65:
		return ConfidenceLevelFirm
	case score > 0.0:
		return ConfidenceLevelTentative
	default:
		return ConfidenceLevelUnknown
	}
}
