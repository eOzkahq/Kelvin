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

// TriageDisposition represents the standardized triage outcome chosen by an analyst.
type TriageDisposition string

const (
	DispositionConfirmed     TriageDisposition = "CONFIRMED"
	DispositionInvestigating TriageDisposition = "INVESTIGATING"
	DispositionFalsePositive TriageDisposition = "FALSE_POSITIVE"
	DispositionAcceptedRisk  TriageDisposition = "ACCEPTED_RISK"
	DispositionDuplicate     TriageDisposition = "DUPLICATE"
)

// TriageScope defines the organizational level to which the triage decision applies.
type TriageScope string

const (
	ScopePersistentFinding TriageScope = "PERSISTENT_FINDING"
	ScopeObservation       TriageScope = "OBSERVATION"
	ScopeCorrelationGroup  TriageScope = "CORRELATION_GROUP"
)

var (
	ErrInvalidDisposition     = errors.New("findings: invalid triage disposition")
	ErrInvalidScope           = errors.New("findings: invalid triage scope")
	ErrJustificationRequired  = errors.New("findings: documented justification is required for triage decision")
	ErrExpiryRequired         = errors.New("findings: exception expiration timestamp is required for accepted risk")
	ErrCanonicalIDRequired    = errors.New("findings: canonical finding ID is required for duplicate disposition")
	ErrSelfReferentialDuplicate = errors.New("findings: finding cannot be marked as a duplicate of itself")
)

var validDispositions = map[TriageDisposition]bool{
	DispositionConfirmed:     true,
	DispositionInvestigating: true,
	DispositionFalsePositive: true,
	DispositionAcceptedRisk:  true,
	DispositionDuplicate:     true,
}

var validScopes = map[TriageScope]bool{
	ScopePersistentFinding: true,
	ScopeObservation:       true,
	ScopeCorrelationGroup:  true,
}

// TriageDecision models an immutable record of an analyst's review outcome.
type TriageDecision struct {
	ID                 uuid.UUID         `json:"id"`
	TenantID           uuid.UUID         `json:"tenant_id"`
	FindingID          uuid.UUID         `json:"finding_id"`
	Disposition        TriageDisposition `json:"disposition"`
	Scope              TriageScope       `json:"scope"`
	ActorID            *uuid.UUID        `json:"actor_id,omitempty"`
	Justification      string            `json:"justification"`
	ApproverID         *uuid.UUID        `json:"approver_id,omitempty"`
	ExpiresAt          *time.Time        `json:"expires_at,omitempty"`
	CanonicalFindingID *uuid.UUID        `json:"canonical_finding_id,omitempty"`
	Metadata           map[string]any    `json:"metadata"`
	CreatedAt          time.Time         `json:"created_at"`
}

// ValidateTriageDecision enforces business rules and required metadata per disposition.
func ValidateTriageDecision(d *TriageDecision) error {
	if d == nil {
		return errors.New("findings: triage decision cannot be nil")
	}
	if d.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if d.FindingID == uuid.Nil {
		return ErrFindingIDRequired
	}
	if !validDispositions[d.Disposition] {
		return fmt.Errorf("%w: %q", ErrInvalidDisposition, d.Disposition)
	}

	scope := d.Scope
	if scope == "" {
		scope = ScopePersistentFinding
		d.Scope = scope
	}
	if !validScopes[scope] {
		return fmt.Errorf("%w: %q", ErrInvalidScope, d.Scope)
	}

	if strings.TrimSpace(d.Justification) == "" {
		return ErrJustificationRequired
	}

	switch d.Disposition {
	case DispositionAcceptedRisk:
		if d.ExpiresAt == nil {
			return ErrExpiryRequired
		}
		if d.ExpiresAt.Before(time.Now().UTC()) {
			return errors.New("findings: exception expiration timestamp must be in the future")
		}
	case DispositionDuplicate:
		if d.CanonicalFindingID == nil || *d.CanonicalFindingID == uuid.Nil {
			return ErrCanonicalIDRequired
		}
		if *d.CanonicalFindingID == d.FindingID {
			return ErrSelfReferentialDuplicate
		}
	}

	return nil
}

// SaveTriageDecision records an immutable triage decision and synchronizes the finding's lifecycle status.
func (r *PostgresFindingRepository) SaveTriageDecision(ctx context.Context, decision *TriageDecision) error {
	if err := ValidateTriageDecision(decision); err != nil {
		return err
	}

	// Verify target finding exists within tenant boundaries
	finding, err := r.GetFindingByID(ctx, decision.TenantID, decision.FindingID)
	if err != nil {
		return err
	}

	// If duplicate disposition, verify canonical parent finding exists within tenant boundaries
	if decision.Disposition == DispositionDuplicate && decision.CanonicalFindingID != nil {
		if _, err := r.GetFindingByID(ctx, decision.TenantID, *decision.CanonicalFindingID); err != nil {
			return fmt.Errorf("findings: canonical finding: %w", err)
		}
	}

	if decision.ID == uuid.Nil {
		decision.ID = uuid.New()
	}
	now := time.Now().UTC()
	if decision.CreatedAt.IsZero() {
		decision.CreatedAt = now
	}
	if decision.Metadata == nil {
		decision.Metadata = make(map[string]any)
	}

	metaBytes, err := json.Marshal(decision.Metadata)
	if err != nil {
		return fmt.Errorf("findings: marshal triage metadata: %w", err)
	}

	const query = `
		INSERT INTO finding_triage_decisions (
			id, tenant_id, finding_id, disposition, scope, actor_id, justification,
			approver_id, expires_at, canonical_finding_id, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
	`

	_, err = r.db.Exec(ctx, query,
		decision.ID,
		decision.TenantID,
		decision.FindingID,
		string(decision.Disposition),
		string(decision.Scope),
		decision.ActorID,
		decision.Justification,
		decision.ApproverID,
		decision.ExpiresAt,
		decision.CanonicalFindingID,
		metaBytes,
		decision.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings: insert triage decision failed: %w", err)
	}

	// Map disposition to lifecycle status transition
	var targetStatus FindingStatus
	switch decision.Disposition {
	case DispositionConfirmed:
		targetStatus = StatusConfirmed
	case DispositionInvestigating:
		targetStatus = StatusInProgress
	case DispositionFalsePositive:
		targetStatus = StatusFalsePositive
	case DispositionAcceptedRisk:
		targetStatus = StatusAcceptedRisk
	case DispositionDuplicate:
		targetStatus = StatusResolved // Marked resolved as duplicate of canonical finding
	}

	// If status differs, perform atomic transition
	if CanonicalStatus(finding.Status) != CanonicalStatus(targetStatus) {
		_, _, err := r.UpdateFindingStatus(
			ctx,
			decision.TenantID,
			decision.FindingID,
			targetStatus,
			decision.ActorID,
			decision.Justification,
			uuid.New(),
		)
		if err != nil {
			return fmt.Errorf("findings: sync status from triage disposition: %w", err)
		}
	}

	return nil
}

// GetTriageDecisionsByFinding retrieves all historical triage decisions for a finding within tenant boundaries.
func (r *PostgresFindingRepository) GetTriageDecisionsByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) ([]*TriageDecision, error) {
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
			id, tenant_id, finding_id, disposition, scope, actor_id, justification,
			approver_id, expires_at, canonical_finding_id, metadata, created_at
		FROM finding_triage_decisions
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY created_at DESC;
	`

	rows, err := r.db.Query(ctx, query, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("findings: query triage decisions failed: %w", err)
	}
	defer rows.Close()

	var decisions []*TriageDecision
	for rows.Next() {
		var d TriageDecision
		var disp, sc string
		var metaBytes []byte

		if err := rows.Scan(
			&d.ID,
			&d.TenantID,
			&d.FindingID,
			&disp,
			&sc,
			&d.ActorID,
			&d.Justification,
			&d.ApproverID,
			&d.ExpiresAt,
			&d.CanonicalFindingID,
			&metaBytes,
			&d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan triage decision row: %w", err)
		}

		d.Disposition = TriageDisposition(disp)
		d.Scope = TriageScope(sc)
		if len(metaBytes) > 0 {
			if err := json.Unmarshal(metaBytes, &d.Metadata); err != nil {
				d.Metadata = make(map[string]any)
			}
		} else {
			d.Metadata = make(map[string]any)
		}

		decisions = append(decisions, &d)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: iterate triage decisions failed: %w", err)
	}

	if decisions == nil {
		decisions = []*TriageDecision{}
	}

	return decisions, nil
}
