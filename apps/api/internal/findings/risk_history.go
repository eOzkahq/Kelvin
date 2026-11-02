package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Trigger reason constants defining why risk recalculation took place.
const (
	TriggerInitialIngestion = "INITIAL_INGESTION"
	TriggerContextUpdate   = "CONTEXT_UPDATE"
	TriggerModelUpgrade    = "MODEL_UPGRADE"
	TriggerManualRequest   = "MANUAL_RECALCULATION"
	TriggerThreatIntel     = "THREAT_INTEL_UPDATE"
)

var (
	ErrRiskHistoryNotFound = errors.New("findings: risk history record not found")
)

// FindingRiskHistoryEntry preserves an immutable point-in-time calculation record.
type FindingRiskHistoryEntry struct {
	ID            uuid.UUID        `json:"id"`
	TenantID      uuid.UUID        `json:"tenant_id"`
	FindingID     uuid.UUID        `json:"finding_id"`
	ModelVersion  string           `json:"model_version"`
	RiskScore     float64          `json:"risk_score"`
	PriorityBand  RiskPriorityBand `json:"priority_band"`
	RiskFactors   map[string]any   `json:"risk_factors"`
	TriggerReason string           `json:"trigger_reason"`
	ActorID       *uuid.UUID       `json:"actor_id,omitempty"`
	CalculatedAt  time.Time        `json:"calculated_at"`
	SupersededAt  time.Time        `json:"superseded_at"`
}

// RecalculateRiskResult represents the outcome of an auditable risk recalculation.
type RecalculateRiskResult struct {
	FindingID     uuid.UUID                `json:"finding_id"`
	PreviousScore *float64                 `json:"previous_score,omitempty"`
	PreviousBand  RiskPriorityBand         `json:"previous_band,omitempty"`
	CurrentScore  float64                  `json:"current_score"`
	CurrentBand   RiskPriorityBand         `json:"current_band"`
	ModelVersion  string                   `json:"model_version"`
	HistoryEntry  *FindingRiskHistoryEntry `json:"history_entry"`
	Explanation   string                   `json:"explanation"`
}

// ArchiveRiskHistory writes a previous calculation into the immutable audit table.
func (r *PostgresFindingRepository) ArchiveRiskHistory(ctx context.Context, entry *FindingRiskHistoryEntry) error {
	if entry == nil {
		return errors.New("findings: risk history entry cannot be nil")
	}
	if entry.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if entry.FindingID == uuid.Nil {
		return ErrFindingIDRequired
	}
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	now := time.Now().UTC()
	if entry.CalculatedAt.IsZero() {
		entry.CalculatedAt = now
	}
	if entry.SupersededAt.IsZero() {
		entry.SupersededAt = now
	}

	factorsJSON, err := json.Marshal(entry.RiskFactors)
	if err != nil {
		factorsJSON = []byte("{}")
	}

	const query = `
		INSERT INTO finding_risk_history (
			id, tenant_id, finding_id, model_version, risk_score,
			priority_band, risk_factors, trigger_reason, actor_id,
			calculated_at, superseded_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		);
	`
	_, err = r.db.Exec(ctx, query,
		entry.ID, entry.TenantID, entry.FindingID, entry.ModelVersion, entry.RiskScore,
		string(entry.PriorityBand), factorsJSON, entry.TriggerReason, entry.ActorID,
		entry.CalculatedAt, entry.SupersededAt,
	)
	if err != nil {
		return fmt.Errorf("findings: archive risk history failed: %w", err)
	}
	return nil
}

// GetRiskHistoryByFinding retrieves historical calculation records for a finding.
func (r *PostgresFindingRepository) GetRiskHistoryByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) ([]*FindingRiskHistoryEntry, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	const query = `
		SELECT
			id, tenant_id, finding_id, model_version, risk_score,
			priority_band, risk_factors, trigger_reason, actor_id,
			calculated_at, superseded_at
		FROM finding_risk_history
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY calculated_at DESC;
	`
	rows, err := r.db.Query(ctx, query, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("findings: query risk history failed: %w", err)
	}
	defer rows.Close()

	var entries []*FindingRiskHistoryEntry
	for rows.Next() {
		var e FindingRiskHistoryEntry
		var bandStr string
		var rawFactors []byte

		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.FindingID, &e.ModelVersion, &e.RiskScore,
			&bandStr, &rawFactors, &e.TriggerReason, &e.ActorID,
			&e.CalculatedAt, &e.SupersededAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan risk history row failed: %w", err)
		}
		e.PriorityBand = RiskPriorityBand(bandStr)
		if len(rawFactors) > 0 {
			_ = json.Unmarshal(rawFactors, &e.RiskFactors)
		}
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: risk history rows iteration error: %w", err)
	}
	return entries, nil
}

// RecalculateFindingRisk executes a versioned recalculation, archiving prior scores and preserving lifecycle status.
func (r *PostgresFindingRepository) RecalculateFindingRisk(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	reason string,
	actorID *uuid.UUID,
) (*RecalculateRiskResult, error) {
	finding, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	if reason == "" {
		reason = TriggerManualRequest
	}

	now := time.Now().UTC()
	var historyEntry *FindingRiskHistoryEntry

	// 1. Archive prior risk score into finding_risk_history if previously scored
	if finding.RiskScore != nil {
		prevModel := RiskModelVersion
		if finding.RiskFactors != nil {
			if v, ok := finding.RiskFactors["model_version"].(string); ok && v != "" {
				prevModel = v
			}
		}
		historyEntry = &FindingRiskHistoryEntry{
			ID:            uuid.New(),
			TenantID:      tenantID,
			FindingID:     findingID,
			ModelVersion:  prevModel,
			RiskScore:     *finding.RiskScore,
			PriorityBand:  finding.RiskPriorityBand,
			RiskFactors:   finding.RiskFactors,
			TriggerReason: reason,
			ActorID:       actorID,
			CalculatedAt:  finding.UpdatedAt,
			SupersededAt:  now,
		}
		if err := r.ArchiveRiskHistory(ctx, historyEntry); err != nil {
			return nil, err
		}
	}

	// 2. Fetch target context if exists
	var trc *TargetRiskContext
	if finding.AffectedEndpoint != "" {
		trc, _ = r.GetTargetRiskContext(ctx, tenantID, finding.ProjectID, finding.AffectedEndpoint)
	}

	// 3. Compute new deterministic score
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

	res, err := CalculateRiskScore(RiskAssessmentInput{
		FindingID:       finding.ID,
		ScannerSeverity: finding.Severity,
		Confidence:      finding.Confidence,
		Exposure:        exp,
		Criticality:     crit,
		Context:         trc,
		Vulnerability: VulnerabilityMetadata{
			CVSSBaseScore: finding.CVSSScore,
			CWEID:         finding.CWEID,
			CVEIDs:        finding.CVEIDs,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("findings: recalculate risk score failed: %w", err)
	}

	// 4. Update finding record (ensuring findings.status remains unaltered)
	factorsJSON, _ := json.Marshal(res.InputFactors)
	const updateQuery = `
		UPDATE findings
		SET risk_score = $1,
		    risk_priority_band = $2,
		    risk_factors = $3,
		    updated_at = $4
		WHERE tenant_id = $5 AND id = $6;
	`
	_, err = r.db.Exec(ctx, updateQuery,
		res.RiskScore, string(res.PriorityBand), factorsJSON, now, tenantID, findingID,
	)
	if err != nil {
		return nil, fmt.Errorf("findings: update finding risk score failed: %w", err)
	}

	return &RecalculateRiskResult{
		FindingID:     findingID,
		PreviousScore: finding.RiskScore,
		PreviousBand:  finding.RiskPriorityBand,
		CurrentScore:  res.RiskScore,
		CurrentBand:   res.PriorityBand,
		ModelVersion:  RiskModelVersion,
		HistoryEntry:  historyEntry,
		Explanation:   res.Explanation,
	}, nil
}
