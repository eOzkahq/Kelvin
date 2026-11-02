package findings

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FactorCategory distinguishes measured technical signals from administrator-supplied context.
const (
	CategoryMeasured      = "MEASURED"
	CategoryManualContext = "MANUAL_CONTEXT"
	CategoryHeuristic     = "HEURISTIC"
)

// RiskFactorItem details an individual contributor to the overall risk assessment.
type RiskFactorItem struct {
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	RawValue    string  `json:"raw_value"`
	ScoreImpact float64 `json:"score_impact,omitempty"`
	Multiplier  float64 `json:"multiplier,omitempty"`
	Description string  `json:"description"`
}

// RiskExplanation provides an auditable, human-readable breakdown of a finding's risk score and priority band.
type RiskExplanation struct {
	FindingID    uuid.UUID        `json:"finding_id"`
	ModelVersion string           `json:"model_version"`
	RiskScore    float64          `json:"risk_score"`
	PriorityBand RiskPriorityBand `json:"priority_band"`
	Summary      string           `json:"summary"`
	Factors      []RiskFactorItem `json:"factors"`
	AssessedAt   time.Time        `json:"assessed_at"`
}

// GenerateRiskExplanation produces a structured factor breakdown and summary narrative for a persistent finding.
// All measured signals and contextual multipliers are explicitly surfaced, and internal secrets are excluded.
func GenerateRiskExplanation(f *PersistentFinding) (*RiskExplanation, error) {
	if f == nil {
		return nil, errors.New("findings: finding cannot be nil")
	}

	score := 0.0
	if f.RiskScore != nil {
		score = *f.RiskScore
	}
	band := f.RiskPriorityBand
	if band == "" {
		band = MapPriorityBand(score)
	}

	modelVersion := RiskModelVersion
	if f.RiskFactors != nil {
		if v, ok := f.RiskFactors["model_version"].(string); ok && v != "" {
			modelVersion = v
		}
	}

	var factors []RiskFactorItem

	// 1. Base Technical Severity (Measured)
	baseSevScore := DeriveBaseSeverity(f.Severity, f.CVSSScore)
	baseDesc := fmt.Sprintf("Baseline impact derived from %s scanner classification", f.Severity)
	if f.CVSSScore != nil {
		baseDesc = fmt.Sprintf("Authoritative CVSS v3.x score %.1f superseded scanner severity", *f.CVSSScore)
	}
	factors = append(factors, RiskFactorItem{
		Name:        "Base Technical Severity",
		Category:    CategoryMeasured,
		RawValue:    f.Severity,
		ScoreImpact: baseSevScore,
		Description: baseDesc,
	})

	// 2. Confidence & Evidentiary Attenuation (Measured)
	conf := f.Confidence
	if conf <= 0.0 || conf > 1.0 {
		conf = 0.80
	}
	confFactor := 0.5 + (conf * 0.5)
	confBand := MapConfidenceBand(conf, false)
	factors = append(factors, RiskFactorItem{
		Name:        "Evidentiary Confidence",
		Category:    CategoryMeasured,
		RawValue:    fmt.Sprintf("%.2f (%s)", conf, confBand),
		Multiplier:  math.Round(confFactor*100) / 100,
		Description: fmt.Sprintf("Proof certainty scaled risk baseline with %.2fx attenuation factor", confFactor),
	})

	// 3. Exposure Context (Manual Context / Discovered)
	var exp TargetExposure = ExposureUnknown
	if f.ScannerData != nil {
		if expStr, ok := f.ScannerData["exposure"].(string); ok {
			exp = TargetExposure(expStr)
		}
	}
	expMult := GetExposureMultiplier(exp)
	expCategory := CategoryManualContext
	if exp == ExposureUnknown {
		expCategory = CategoryHeuristic
	}
	factors = append(factors, RiskFactorItem{
		Name:        "Target Exposure",
		Category:    expCategory,
		RawValue:    string(exp),
		Multiplier:  expMult,
		Description: fmt.Sprintf("Network reachability factor (x%.2f multiplier applied)", expMult),
	})

	// 4. Asset Criticality (Manual Context)
	var crit AssetCriticality = CriticalityUnknown
	if f.ScannerData != nil {
		if critStr, ok := f.ScannerData["criticality"].(string); ok {
			crit = AssetCriticality(critStr)
		}
	}
	critMult := GetCriticalityMultiplier(crit)
	critCategory := CategoryManualContext
	if crit == CriticalityUnknown {
		critCategory = CategoryHeuristic
	}
	factors = append(factors, RiskFactorItem{
		Name:        "Asset Criticality",
		Category:    critCategory,
		RawValue:    string(crit),
		Multiplier:  critMult,
		Description: fmt.Sprintf("Business impact tier factor (x%.2f multiplier applied)", critMult),
	})

	// 5. Threat Intelligence Signals (Measured)
	var threatBoost float64
	var threatItems []string
	if f.ScannerData != nil {
		if ke, ok := f.ScannerData["known_exploited"].(bool); ok && ke {
			threatBoost += 1.0
			threatItems = append(threatItems, "CISA KEV Known Exploited (+1.0)")
		}
		if epss, ok := f.ScannerData["epss_score"].(float64); ok && epss >= 0.50 {
			threatBoost += 0.5
			threatItems = append(threatItems, fmt.Sprintf("High EPSS %.2f (+0.5)", epss))
		}
	}
	if threatBoost > 0 {
		factors = append(factors, RiskFactorItem{
			Name:        "Threat Intelligence Boost",
			Category:    CategoryMeasured,
			RawValue:    strings.Join(threatItems, ", "),
			ScoreImpact: threatBoost,
			Description: "Active exploitation signals elevated operational urgency",
		})
	}

	// 6. Target Context Multiplier (Manual Context, if present)
	if f.ScannerData != nil {
		if ctxSignals, ok := f.ScannerData["context_signals"].([]string); ok && len(ctxSignals) > 0 {
			factors = append(factors, RiskFactorItem{
				Name:        "Target Risk Context",
				Category:    CategoryManualContext,
				RawValue:    strings.Join(ctxSignals, "; "),
				Multiplier:  1.0,
				Description: "Verified target context adjustments (environment, internet reachability, PII sensitivity)",
			})
		}
	}

	// Construct human-readable summary
	summary := fmt.Sprintf(
		"Finding assigned %s priority (score %.1f) by model %s. Base severity %.1f scaled by confidence %.2f (%.2fx factor)",
		band,
		score,
		modelVersion,
		baseSevScore,
		conf,
		confFactor,
	)
	if expMult != 1.0 || critMult != 1.0 {
		summary += fmt.Sprintf(" with exposure (x%.2f) and criticality (x%.2f) modifiers", expMult, critMult)
	}
	if threatBoost > 0 {
		summary += fmt.Sprintf(" and +%.1f threat intelligence boost (%s)", threatBoost, strings.Join(threatItems, ", "))
	}
	summary += "."

	assessedAt := f.UpdatedAt
	if assessedAt.IsZero() {
		assessedAt = time.Now().UTC()
	}

	return &RiskExplanation{
		FindingID:    f.ID,
		ModelVersion: modelVersion,
		RiskScore:    score,
		PriorityBand: band,
		Summary:      summary,
		Factors:      factors,
		AssessedAt:   assessedAt,
	}, nil
}


// GetRiskExplanation loads a finding within tenant boundaries and generates an auditable risk explanation.
func (r *PostgresFindingRepository) GetRiskExplanation(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) (*RiskExplanation, error) {
	f, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	return GenerateRiskExplanation(f)
}
