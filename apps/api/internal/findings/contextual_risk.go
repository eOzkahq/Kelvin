package findings

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

// TargetEnvironment categorizes the deployment boundary of the target.
type TargetEnvironment string

const (
	EnvProduction  TargetEnvironment = "PRODUCTION"
	EnvStaging     TargetEnvironment = "STAGING"
	EnvDevelopment TargetEnvironment = "DEVELOPMENT"
	EnvUnknown     TargetEnvironment = "UNKNOWN"
)

// BusinessCriticality represents the business impact ranking of the system.
type BusinessCriticality string

const (
	CritMissionCritical     BusinessCriticality = "MISSION_CRITICAL"
	CritBusinessOperational BusinessCriticality = "BUSINESS_OPERATIONAL"
	CritNonCritical         BusinessCriticality = "NON_CRITICAL"
	CritUnknown             BusinessCriticality = "UNKNOWN"
)

var (
	ErrTargetAssetRequired        = errors.New("findings: target_asset is required for contextual risk")
	ErrInvalidEnvironment         = errors.New("findings: invalid target environment")
	ErrInvalidCriticality         = errors.New("findings: invalid business criticality")
	ErrTargetRiskContextNotFound  = errors.New("findings: target risk context not found")
)

var validEnvironments = map[TargetEnvironment]bool{
	EnvProduction:  true,
	EnvStaging:     true,
	EnvDevelopment: true,
	EnvUnknown:     true,
}

var validCriticalities = map[BusinessCriticality]bool{
	CritMissionCritical:     true,
	CritBusinessOperational: true,
	CritNonCritical:         true,
	CritUnknown:             true,
}

// TargetRiskContext models administrator or inventory-defined risk attributes of a target asset.
type TargetRiskContext struct {
	ID                  uuid.UUID           `json:"id"`
	TenantID            uuid.UUID           `json:"tenant_id"`
	ProjectID           uuid.UUID           `json:"project_id"`
	TargetAsset         string              `json:"target_asset"`
	Environment         TargetEnvironment   `json:"environment"`
	InternetFacing      bool                `json:"internet_facing"`
	ContainsPII         bool                `json:"contains_pii"`
	BusinessCriticality BusinessCriticality `json:"business_criticality"`
	Source              string              `json:"source"`
	UpdatedBy           *uuid.UUID          `json:"updated_by,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

// ValidateTargetRiskContext enforces data validity and approved values.
func ValidateTargetRiskContext(c *TargetRiskContext) error {
	if c == nil {
		return errors.New("findings: target risk context cannot be nil")
	}
	if c.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if c.ProjectID == uuid.Nil {
		return ErrProjectRequired
	}
	normAsset := normalization.NormalizeAsset(c.TargetAsset)
	if normAsset == "" {
		return ErrTargetAssetRequired
	}
	c.TargetAsset = normAsset

	if c.Environment == "" {
		c.Environment = EnvUnknown
	}
	if !validEnvironments[c.Environment] {
		return fmt.Errorf("%w: %q", ErrInvalidEnvironment, c.Environment)
	}

	if c.BusinessCriticality == "" {
		c.BusinessCriticality = CritUnknown
	}
	if !validCriticalities[c.BusinessCriticality] {
		return fmt.Errorf("%w: %q", ErrInvalidCriticality, c.BusinessCriticality)
	}

	if c.Source == "" {
		c.Source = "MANUAL_ANALYST"
	}

	return nil
}

// CalculateContextualMultiplier computes a composite risk multiplier and explainability breakdown.
// Missing context defaults strictly to 1.0 (neutral) so unestablished context never fabricates risk.
func CalculateContextualMultiplier(c *TargetRiskContext) (float64, []string) {
	if c == nil {
		return 1.0, []string{"Target Context: UNKNOWN (x1.00)"}
	}

	var signals []string
	mult := 1.0

	// 1. Deployment Environment
	switch c.Environment {
	case EnvProduction:
		mult *= 1.20
		signals = append(signals, "Env: PRODUCTION (x1.20)")
	case EnvStaging:
		mult *= 0.90
		signals = append(signals, "Env: STAGING (x0.90)")
	case EnvDevelopment:
		mult *= 0.70
		signals = append(signals, "Env: DEVELOPMENT (x0.70)")
	case EnvUnknown, "":
		signals = append(signals, "Env: UNKNOWN (x1.00)")
	}

	// 2. Internet Reachability
	if c.InternetFacing {
		mult *= 1.15
		signals = append(signals, "Exposure: Internet-Facing (x1.15)")
	} else {
		mult *= 0.90
		signals = append(signals, "Exposure: Internal/Private (x0.90)")
	}

	// 3. Data Sensitivity (PII/Financial)
	if c.ContainsPII {
		mult *= 1.25
		signals = append(signals, "Data: Contains PII/Sensitive Data (x1.25)")
	}

	// 4. Business Criticality Tier
	switch c.BusinessCriticality {
	case CritMissionCritical:
		mult *= 1.30
		signals = append(signals, "Criticality: MISSION_CRITICAL (x1.30)")
	case CritBusinessOperational:
		mult *= 1.10
		signals = append(signals, "Criticality: BUSINESS_OPERATIONAL (x1.10)")
	case CritNonCritical:
		mult *= 0.80
		signals = append(signals, "Criticality: NON_CRITICAL (x0.80)")
	case CritUnknown, "":
		signals = append(signals, "Criticality: UNKNOWN (x1.00)")
	}

	return mult, signals
}

// UpsertTargetRiskContext saves or updates target contextual risk factors for a project and asset.
func (r *PostgresFindingRepository) UpsertTargetRiskContext(ctx context.Context, trc *TargetRiskContext) error {
	if err := ValidateTargetRiskContext(trc); err != nil {
		return err
	}

	if trc.ID == uuid.Nil {
		trc.ID = uuid.New()
	}
	now := time.Now().UTC()
	if trc.CreatedAt.IsZero() {
		trc.CreatedAt = now
	}
	trc.UpdatedAt = now

	const query = `
		INSERT INTO target_risk_contexts (
			id, tenant_id, project_id, target_asset, environment,
			internet_facing, contains_pii, business_criticality, source,
			updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (tenant_id, project_id, target_asset) DO UPDATE SET
			environment = EXCLUDED.environment,
			internet_facing = EXCLUDED.internet_facing,
			contains_pii = EXCLUDED.contains_pii,
			business_criticality = EXCLUDED.business_criticality,
			source = EXCLUDED.source,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at;
	`

	_, err := r.db.Exec(ctx, query,
		trc.ID, trc.TenantID, trc.ProjectID, trc.TargetAsset, string(trc.Environment),
		trc.InternetFacing, trc.ContainsPII, string(trc.BusinessCriticality), trc.Source,
		trc.UpdatedBy, trc.CreatedAt, trc.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: upsert target risk context failed: %w", err)
	}

	return nil
}

// GetTargetRiskContext retrieves the contextual risk definition for an asset within tenant boundaries.
func (r *PostgresFindingRepository) GetTargetRiskContext(
	ctx context.Context,
	tenantID, projectID uuid.UUID,
	targetAsset string,
) (*TargetRiskContext, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if projectID == uuid.Nil {
		return nil, ErrProjectRequired
	}
	normAsset := normalization.NormalizeAsset(targetAsset)
	if normAsset == "" {
		return nil, ErrTargetAssetRequired
	}

	const query = `
		SELECT
			id, tenant_id, project_id, target_asset, environment,
			internet_facing, contains_pii, business_criticality, source,
			updated_by, created_at, updated_at
		FROM target_risk_contexts
		WHERE tenant_id = $1 AND project_id = $2 AND target_asset = $3
		LIMIT 1;
	`
	row := r.db.QueryRow(ctx, query, tenantID, projectID, normAsset)

	var trc TargetRiskContext
	var envStr, critStr string

	if err := row.Scan(
		&trc.ID, &trc.TenantID, &trc.ProjectID, &trc.TargetAsset, &envStr,
		&trc.InternetFacing, &trc.ContainsPII, &critStr, &trc.Source,
		&trc.UpdatedBy, &trc.CreatedAt, &trc.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTargetRiskContextNotFound
		}
		return nil, err
	}

	trc.Environment = TargetEnvironment(envStr)
	trc.BusinessCriticality = BusinessCriticality(critStr)

	return &trc, nil
}
