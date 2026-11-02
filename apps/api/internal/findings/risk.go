package findings

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RiskPriorityBand defines the discrete operational urgency category.
type RiskPriorityBand string

const (
	RiskBandCritical RiskPriorityBand = "CRITICAL" // 9.0 - 10.0
	RiskBandHigh     RiskPriorityBand = "HIGH"     // 7.0 - 8.9
	RiskBandMedium   RiskPriorityBand = "MEDIUM"   // 4.0 - 6.9
	RiskBandLow      RiskPriorityBand = "LOW"      // 0.1 - 3.9
	RiskBandInfo     RiskPriorityBand = "INFO"     // 0.0
)

// TargetExposure defines network reachability context.
type TargetExposure string

const (
	ExposurePublicInternet TargetExposure = "PUBLIC_INTERNET"
	ExposureInternalVPC    TargetExposure = "INTERNAL_VPC"
	ExposureIsolated       TargetExposure = "ISOLATED"
	ExposureUnknown        TargetExposure = "UNKNOWN"
)

// AssetCriticality defines the business impact tier of the affected system.
type AssetCriticality string

const (
	CriticalityTier1   AssetCriticality = "TIER_1_CRITICAL"
	CriticalityTier2   AssetCriticality = "TIER_2_HIGH"
	CriticalityTier3   AssetCriticality = "TIER_3_MEDIUM"
	CriticalityTier4   AssetCriticality = "TIER_4_LOW"
	CriticalityUnknown AssetCriticality = "UNKNOWN"
)

var (
	ErrScannerSeverityRequired = errors.New("findings: scanner severity is required for risk assessment")
)

// VulnerabilityMetadata holds threat intelligence signals.
type VulnerabilityMetadata struct {
	CVSSBaseScore   *float64 `json:"cvss_base_score,omitempty"`
	EPSSScore       *float64 `json:"epss_score,omitempty"`
	KnownExploited  bool     `json:"known_exploited"`
	CWEID           string   `json:"cwe_id,omitempty"`
	CVEIDs          []string `json:"cve_ids,omitempty"`
}

// RiskAssessmentInput supplies required and contextual parameters into the KELVIN Risk Engine.
type RiskAssessmentInput struct {
	FindingID       uuid.UUID             `json:"finding_id"`
	ScannerSeverity string                `json:"scanner_severity"` // Mandatory
	Confidence      float64               `json:"confidence"`       // Mandatory [0.0, 1.0]
	Exposure        TargetExposure        `json:"exposure"`         // Optional (default UNKNOWN)
	Criticality     AssetCriticality      `json:"criticality"`      // Optional (default UNKNOWN)
	Vulnerability   VulnerabilityMetadata `json:"vulnerability"`    // Optional
	Context         *TargetRiskContext    `json:"context,omitempty"`// Optional target risk context
}

// RiskAssessmentResult provides the calculated risk score, priority band, and mathematical explanation.
type RiskAssessmentResult struct {
	FindingID             uuid.UUID         `json:"finding_id"`
	RiskScore             float64           `json:"risk_score"`
	PriorityBand          RiskPriorityBand  `json:"priority_band"`
	ScannerSeverity       string            `json:"scanner_severity"`
	BaseSeverityScore     float64           `json:"base_severity_score"`
	ConfidenceFactor      float64           `json:"confidence_factor"`
	ExposureMultiplier    float64           `json:"exposure_multiplier"`
	CriticalityMultiplier float64           `json:"criticality_multiplier"`
	ExploitabilityBoost   float64           `json:"exploitability_boost"`
	Explanation           string            `json:"explanation"`
	InputFactors          map[string]any    `json:"input_factors"`
	AssessedAt            time.Time         `json:"assessed_at"`
}

// DeriveBaseSeverity converts raw scanner severity or CVSS into a baseline score (0.0 to 10.0).
func DeriveBaseSeverity(severity string, cvss *float64) float64 {
	if cvss != nil && *cvss >= 0.0 && *cvss <= 10.0 {
		return *cvss
	}

	norm := strings.ToUpper(strings.TrimSpace(severity))
	switch norm {
	case "CRITICAL":
		return 9.5
	case "HIGH":
		return 8.0
	case "MEDIUM":
		return 5.5
	case "LOW":
		return 2.5
	case "INFO", "INFORMATIONAL":
		return 0.0
	default:
		return 5.0
	}
}

// GetExposureMultiplier returns the risk coefficient for the target exposure context.
// Missing or unknown context defaults to neutral (1.0).
func GetExposureMultiplier(exp TargetExposure) float64 {
	switch exp {
	case ExposurePublicInternet:
		return 1.20
	case ExposureInternalVPC:
		return 0.85
	case ExposureIsolated:
		return 0.50
	case ExposureUnknown, "":
		return 1.00
	default:
		return 1.00
	}
}

// GetCriticalityMultiplier returns the risk coefficient for the affected asset criticality tier.
// Missing or unknown context defaults to neutral (1.0).
func GetCriticalityMultiplier(crit AssetCriticality) float64 {
	switch crit {
	case CriticalityTier1:
		return 1.25
	case CriticalityTier2:
		return 1.10
	case CriticalityTier3:
		return 1.00
	case CriticalityTier4:
		return 0.80
	case CriticalityUnknown, "":
		return 1.00
	default:
		return 1.00
	}
}

// MapPriorityBand categorizes a numeric risk score (0.0 - 10.0) into its discrete operational band.
func MapPriorityBand(score float64) RiskPriorityBand {
	switch {
	case score >= 9.0:
		return RiskBandCritical
	case score >= 7.0:
		return RiskBandHigh
	case score >= 4.0:
		return RiskBandMedium
	case score > 0.0:
		return RiskBandLow
	default:
		return RiskBandInfo
	}
}

// CalculateRiskScore evaluates finding attributes and contextual factors to produce a reproducible risk score.
func CalculateRiskScore(input RiskAssessmentInput) (*RiskAssessmentResult, error) {
	if strings.TrimSpace(input.ScannerSeverity) == "" {
		return nil, ErrScannerSeverityRequired
	}

	conf := input.Confidence
	if conf <= 0.0 || conf > 1.0 {
		conf = 0.8 // Conservative default confidence if omitted
	}

	baseSeverity := DeriveBaseSeverity(input.ScannerSeverity, input.Vulnerability.CVSSBaseScore)

	// If base severity is 0.0 (INFO) and no CVSS is defined, risk remains INFO (0.0)
	if baseSeverity == 0.0 {
		return &RiskAssessmentResult{
			FindingID:             input.FindingID,
			RiskScore:             0.0,
			PriorityBand:          RiskBandInfo,
			ScannerSeverity:       input.ScannerSeverity,
			BaseSeverityScore:     0.0,
			ConfidenceFactor:      1.0,
			ExposureMultiplier:    1.0,
			CriticalityMultiplier: 1.0,
			ExploitabilityBoost:   0.0,
			Explanation:           "Informational finding: no direct risk impact.",
			InputFactors: map[string]any{
				"scanner_severity": input.ScannerSeverity,
			},
			AssessedAt: time.Now().UTC(),
		}, nil
	}

	// Confidence attenuation: maps confidence [0.0, 1.0] to [0.5, 1.0]
	// This bounds reduction so even tentative high-severity findings maintain baseline visibility.
	confFactor := 0.5 + (conf * 0.5)

	expMult := GetExposureMultiplier(input.Exposure)
	critMult := GetCriticalityMultiplier(input.Criticality)

	// Threat intelligence boost
	exploitBoost := 0.0
	var threatSignals []string
	if input.Vulnerability.KnownExploited {
		exploitBoost += 1.0
		threatSignals = append(threatSignals, "Known Exploited (CISA KEV)")
	}
	if input.Vulnerability.EPSSScore != nil && *input.Vulnerability.EPSSScore >= 0.50 {
		exploitBoost += 0.5
		threatSignals = append(threatSignals, fmt.Sprintf("High EPSS (%.2f)", *input.Vulnerability.EPSSScore))
	}

	// Contextual multiplier
	contextMult := 1.0
	var contextSignals []string
	if input.Context != nil {
		contextMult, contextSignals = CalculateContextualMultiplier(input.Context)
	}

	// Composite Risk Formula:
	// RawScore = (BaseSeverity * ConfidenceFactor * ExposureMultiplier * CriticalityMultiplier * ContextMultiplier) + ExploitBoost
	rawScore := (baseSeverity * confFactor * expMult * critMult * contextMult) + exploitBoost

	// Clamp to [0.1, 10.0] range
	if rawScore > 10.0 {
		rawScore = 10.0
	} else if rawScore < 0.1 {
		rawScore = 0.1
	}

	// Rounded to 1 decimal place to prevent unsupported pseudo-precision
	finalScore := math.Round(rawScore*10) / 10

	priorityBand := MapPriorityBand(finalScore)

	// Construct mathematical explainability narrative
	expDetails := string(input.Exposure)
	if expDetails == "" {
		expDetails = "UNKNOWN"
	}
	critDetails := string(input.Criticality)
	if critDetails == "" {
		critDetails = "UNKNOWN"
	}

	threatSummary := "None"
	if len(threatSignals) > 0 {
		threatSummary = strings.Join(threatSignals, ", ")
	}

	var explanation string
	if len(contextSignals) > 0 {
		contextDetails := strings.Join(contextSignals, ", ")
		explanation = fmt.Sprintf(
			"Base Severity: %.1f | Confidence: %.2f (factor %.2f) | Exposure: %s (x%.2f) | Asset Criticality: %s (x%.2f) | Target Context: [%s] (x%.2f) | Threat Boost: +%.1f (%s) -> Final Risk: %.1f [%s]",
			baseSeverity,
			conf,
			confFactor,
			expDetails,
			expMult,
			critDetails,
			critMult,
			contextDetails,
			contextMult,
			exploitBoost,
			threatSummary,
			finalScore,
			priorityBand,
		)
	} else {
		explanation = fmt.Sprintf(
			"Base Severity: %.1f | Confidence: %.2f (factor %.2f) | Exposure: %s (x%.2f) | Asset Criticality: %s (x%.2f) | Threat Boost: +%.1f (%s) -> Final Risk: %.1f [%s]",
			baseSeverity,
			conf,
			confFactor,
			expDetails,
			expMult,
			critDetails,
			critMult,
			exploitBoost,
			threatSummary,
			finalScore,
			priorityBand,
		)
	}

	return &RiskAssessmentResult{
		FindingID:             input.FindingID,
		RiskScore:             finalScore,
		PriorityBand:          priorityBand,
		ScannerSeverity:       input.ScannerSeverity,
		BaseSeverityScore:     baseSeverity,
		ConfidenceFactor:      confFactor,
		ExposureMultiplier:    expMult,
		CriticalityMultiplier: critMult,
		ExploitabilityBoost:   exploitBoost,
		Explanation:           explanation,
		InputFactors: map[string]any{
			"scanner_severity":       input.ScannerSeverity,
			"confidence":             conf,
			"exposure":               expDetails,
			"exposure_multiplier":    expMult,
			"criticality":            critDetails,
			"criticality_multiplier": critMult,
			"threat_signals":         threatSignals,
			"exploitability_boost":   exploitBoost,
			"model_version":         RiskModelVersion,
		},
		AssessedAt: time.Now().UTC(),
	}, nil
}

const (
	EngineVersion    = "v1"
	RiskModelVersion = "kelvin.risk_engine.v1"
)

// RiskEngine computes deterministic risk scores and priority bands for findings.
type RiskEngine struct {
	version string
}

// NewRiskEngine creates a new deterministic risk scoring engine instance.
func NewRiskEngine() *RiskEngine {
	return &RiskEngine{version: EngineVersion}
}

// Version returns the active scoring algorithm specification version.
func (e *RiskEngine) Version() string {
	return e.version
}

// Compute processes a persistent finding through the deterministic scoring model.
func (e *RiskEngine) Compute(finding *PersistentFinding) (*RiskAssessmentResult, error) {
	if finding == nil {
		return nil, errors.New("findings: finding cannot be nil")
	}
	var exp TargetExposure = ExposureUnknown
	var crit AssetCriticality = CriticalityUnknown
	if finding.ScannerData != nil {
		if expStr, ok := finding.ScannerData["exposure"].(string); ok {
			exp = TargetExposure(expStr)
		}
		if critStr, ok := finding.ScannerData["criticality"].(string); ok {
			crit = AssetCriticality(critStr)
		}
	}

	return CalculateRiskScore(RiskAssessmentInput{
		FindingID:       finding.ID,
		ScannerSeverity: finding.Severity,
		Confidence:      finding.Confidence,
		Exposure:        exp,
		Criticality:     crit,
		Vulnerability: VulnerabilityMetadata{
			CVSSBaseScore: finding.CVSSScore,
			CWEID:         finding.CWEID,
			CVEIDs:        finding.CVEIDs,
		},
	})
}
