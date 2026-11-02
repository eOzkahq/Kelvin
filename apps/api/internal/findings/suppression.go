package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SuppressionStatus represents the lifecycle state of a finding suppression rule.
type SuppressionStatus string

const (
	SuppressionActive  SuppressionStatus = "ACTIVE"
	SuppressionExpired SuppressionStatus = "EXPIRED"
	SuppressionRevoked SuppressionStatus = "REVOKED"
)

var (
	ErrSuppressionReasonRequired = errors.New("findings: documented justification is required for suppression")
	ErrSuppressionExpiryRequired = errors.New("findings: suppression expiration timestamp must be in the future")
	ErrSuppressionAlreadyActive  = errors.New("findings: finding is already under an active suppression rule")
	ErrSuppressionNotFound       = errors.New("findings: active suppression rule not found")
	ErrRevocationReasonRequired  = errors.New("findings: reason is required to revoke a suppression rule")
)

var validSuppressionStatuses = map[SuppressionStatus]bool{
	SuppressionActive:  true,
	SuppressionExpired: true,
	SuppressionRevoked: true,
}

// SuppressionRule models a bounded, temporary exclusion rule for a persistent finding.
type SuppressionRule struct {
	ID               uuid.UUID         `json:"id"`
	TenantID         uuid.UUID         `json:"tenant_id"`
	FindingID        uuid.UUID         `json:"finding_id"`
	ActorID          *uuid.UUID        `json:"actor_id,omitempty"`
	Reason           string            `json:"reason"`
	Status           SuppressionStatus `json:"status"`
	ExpiresAt        time.Time         `json:"expires_at"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy        *uuid.UUID        `json:"revoked_by,omitempty"`
	RevocationReason string            `json:"revocation_reason,omitempty"`
	Metadata         map[string]any    `json:"metadata"`
	CreatedAt        time.Time         `json:"created_at"`
}

// IsActive returns whether this suppression rule is currently in effect and unexpired.
func (r *SuppressionRule) IsActive(now time.Time) bool {
	if r == nil {
		return false
	}
	if r.Status != SuppressionActive {
		return false
	}
	return now.Before(r.ExpiresAt)
}

// ValidateSuppressionRule enforces business and security rules on new suppression rules.
func ValidateSuppressionRule(rule *SuppressionRule, now time.Time) error {
	if rule == nil {
		return errors.New("findings: suppression rule cannot be nil")
	}
	if rule.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if rule.FindingID == uuid.Nil {
		return ErrFindingIDRequired
	}
	if strings.TrimSpace(rule.Reason) == "" {
		return ErrSuppressionReasonRequired
	}
	if rule.ExpiresAt.IsZero() || !rule.ExpiresAt.After(now) {
		return ErrSuppressionExpiryRequired
	}
	if rule.Status == "" {
		rule.Status = SuppressionActive
	}
	if !validSuppressionStatuses[rule.Status] {
		return fmt.Errorf("findings: invalid suppression status %q", rule.Status)
	}
	return nil
}

// CreateSuppressionRule records a temporary suppression rule for a finding within tenant boundaries.
func (r *PostgresFindingRepository) CreateSuppressionRule(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	actorID *uuid.UUID,
	reason string,
	expiresAt time.Time,
	corrID uuid.UUID,
) (*SuppressionRule, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	// 1. Verify finding exists within tenant boundary
	finding, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rule := &SuppressionRule{
		ID:        uuid.New(),
		TenantID:  tenantID,
		FindingID: findingID,
		ActorID:   actorID,
		Reason:    reason,
		Status:    SuppressionActive,
		ExpiresAt: expiresAt.UTC(),
		Metadata:  make(map[string]any),
		CreatedAt: now,
	}

	if err := ValidateSuppressionRule(rule, now); err != nil {
		return nil, err
	}

	// 2. Check if an active, unexpired suppression already exists
	active, err := r.GetActiveSuppression(ctx, tenantID, findingID)
	if err == nil && active != nil && active.IsActive(now) {
		return nil, ErrSuppressionAlreadyActive
	}

	// 3. Persist suppression rule
	metaBytes, err := json.Marshal(rule.Metadata)
	if err != nil {
		return nil, fmt.Errorf("findings: marshal suppression metadata: %w", err)
	}

	const query = `
		INSERT INTO finding_suppression_rules (
			id, tenant_id, finding_id, actor_id, reason, status,
			expires_at, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	`
	if _, err := r.db.Exec(ctx, query,
		rule.ID,
		rule.TenantID,
		rule.FindingID,
		rule.ActorID,
		rule.Reason,
		string(rule.Status),
		rule.ExpiresAt,
		metaBytes,
		rule.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("findings: insert suppression rule failed: %w", err)
	}

	// 4. Record timeline event
	_ = r.RecordTimelineEvent(ctx, &TimelineEntry{
		ID:        uuid.New(),
		TenantID:  tenantID,
		FindingID: finding.ID,
		ActorID:   actorID,
		EventType: TimelineEventSuppressionCreated,
		Payload: map[string]any{
			"suppression_id": rule.ID.String(),
			"reason":         rule.Reason,
			"expires_at":     rule.ExpiresAt.Format(time.RFC3339),
		},
		CorrelationID: corrID,
		CreatedAt:     now,
	})

	return rule, nil
}

// RevokeSuppressionRule cancels an active suppression rule, immediately returning the finding to standard review.
func (r *PostgresFindingRepository) RevokeSuppressionRule(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	actorID *uuid.UUID,
	revocationReason string,
	corrID uuid.UUID,
) (*SuppressionRule, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}
	if strings.TrimSpace(revocationReason) == "" {
		return nil, ErrRevocationReasonRequired
	}

	// Verify finding exists in tenant
	finding, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	active, err := r.GetActiveSuppression(ctx, tenantID, findingID)
	if err != nil || active == nil {
		return nil, ErrSuppressionNotFound
	}

	now := time.Now().UTC()
	active.Status = SuppressionRevoked
	active.RevokedAt = &now
	active.RevokedBy = actorID
	active.RevocationReason = revocationReason

	const updateQuery = `
		UPDATE finding_suppression_rules
		SET status = $1, revoked_at = $2, revoked_by = $3, revocation_reason = $4
		WHERE id = $5 AND tenant_id = $6;
	`
	if _, err := r.db.Exec(ctx, updateQuery,
		string(SuppressionRevoked),
		active.RevokedAt,
		active.RevokedBy,
		active.RevocationReason,
		active.ID,
		tenantID,
	); err != nil {
		return nil, fmt.Errorf("findings: revoke suppression rule failed: %w", err)
	}

	// Record timeline event
	_ = r.RecordTimelineEvent(ctx, &TimelineEntry{
		ID:        uuid.New(),
		TenantID:  tenantID,
		FindingID: finding.ID,
		ActorID:   actorID,
		EventType: TimelineEventSuppressionRevoked,
		Payload: map[string]any{
			"suppression_id":    active.ID.String(),
			"revocation_reason": revocationReason,
		},
		CorrelationID: corrID,
		CreatedAt:     now,
	})

	return active, nil
}

// GetActiveSuppression retrieves the current active suppression rule for a finding, if present and unexpired.
func (r *PostgresFindingRepository) GetActiveSuppression(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) (*SuppressionRule, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	const query = `
		SELECT
			id, tenant_id, finding_id, actor_id, reason, status,
			expires_at, revoked_at, revoked_by, revocation_reason, metadata, created_at
		FROM finding_suppression_rules
		WHERE tenant_id = $1 AND finding_id = $2 AND status = 'ACTIVE'
		ORDER BY created_at DESC
		LIMIT 1;
	`
	row := r.db.QueryRow(ctx, query, tenantID, findingID)

	var rule SuppressionRule
	var statusStr string
	var metaBytes []byte
	var revReason *string

	if err := row.Scan(
		&rule.ID,
		&rule.TenantID,
		&rule.FindingID,
		&rule.ActorID,
		&rule.Reason,
		&statusStr,
		&rule.ExpiresAt,
		&rule.RevokedAt,
		&rule.RevokedBy,
		&revReason,
		&metaBytes,
		&rule.CreatedAt,
	); err != nil {
		return nil, ErrSuppressionNotFound
	}

	rule.Status = SuppressionStatus(statusStr)
	if revReason != nil {
		rule.RevocationReason = *revReason
	}
	if len(metaBytes) > 0 {
		_ = json.Unmarshal(metaBytes, &rule.Metadata)
	}
	if rule.Metadata == nil {
		rule.Metadata = make(map[string]any)
	}

	// Check if rule has expired past now()
	now := time.Now().UTC()
	if !rule.ExpiresAt.After(now) {
		// Rule has passed expiration timestamp: automatically transition status to EXPIRED
		rule.Status = SuppressionExpired
		const expireQuery = `
			UPDATE finding_suppression_rules
			SET status = 'EXPIRED'
			WHERE id = $1 AND tenant_id = $2;
		`
		_, _ = r.db.Exec(ctx, expireQuery, rule.ID, tenantID)
		return nil, ErrSuppressionNotFound
	}

	return &rule, nil
}

// GetSuppressionsByFinding lists all historical and active suppression rules for a finding.
func (r *PostgresFindingRepository) GetSuppressionsByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) ([]*SuppressionRule, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	// Verify finding exists in tenant / anti-IDOR
	if _, err := r.GetFindingByID(ctx, tenantID, findingID); err != nil {
		return nil, err
	}

	const query = `
		SELECT
			id, tenant_id, finding_id, actor_id, reason, status,
			expires_at, revoked_at, revoked_by, revocation_reason, metadata, created_at
		FROM finding_suppression_rules
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY created_at DESC;
	`
	rows, err := r.db.Query(ctx, query, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("findings: query suppression rules failed: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	var rules []*SuppressionRule
	for rows.Next() {
		var rule SuppressionRule
		var statusStr string
		var metaBytes []byte
		var revReason *string

		if err := rows.Scan(
			&rule.ID,
			&rule.TenantID,
			&rule.FindingID,
			&rule.ActorID,
			&rule.Reason,
			&statusStr,
			&rule.ExpiresAt,
			&rule.RevokedAt,
			&rule.RevokedBy,
			&revReason,
			&metaBytes,
			&rule.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan suppression rule row: %w", err)
		}

		rule.Status = SuppressionStatus(statusStr)
		if revReason != nil {
			rule.RevocationReason = *revReason
		}
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &rule.Metadata)
		}
		if rule.Metadata == nil {
			rule.Metadata = make(map[string]any)
		}

		if rule.Status == SuppressionActive && !rule.ExpiresAt.After(now) {
			rule.Status = SuppressionExpired
		}

		rules = append(rules, &rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: iterate suppression rules: %w", err)
	}

	return rules, nil
}
