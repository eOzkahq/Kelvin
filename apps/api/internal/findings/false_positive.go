package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/normalization"
)

// FalsePositiveAction defines the auditable action taken on a false-positive decision.
type FalsePositiveAction string

const (
	ActionMarkedFalsePositive FalsePositiveAction = "MARKED_FALSE_POSITIVE"
	ActionReversed            FalsePositiveAction = "REVERSED"
	ActionReviewFlagged       FalsePositiveAction = "REVIEW_FLAGGED"

	// MinRationaleLength enforces that analysts provide substantive justification (>= 20 characters).
	MinRationaleLength = 20
)

var (
	ErrRationaleTooShort      = errors.New("findings: false-positive justification must be at least 20 characters")
	ErrInvalidAction          = errors.New("findings: invalid false-positive action")
	ErrNotFalsePositive       = errors.New("findings: finding is not currently marked as false positive")
	ErrAlreadyFalsePositive   = errors.New("findings: finding is already marked as false positive")
	ErrActorRequired          = errors.New("findings: actor ID is required for false-positive decision")
	ErrTargetStatusRequired   = errors.New("findings: target status is required for false-positive reversal")
)

var validActions = map[FalsePositiveAction]bool{
	ActionMarkedFalsePositive: true,
	ActionReversed:            true,
	ActionReviewFlagged:       true,
}

// FalsePositiveReview models an immutable decision record in the false-positive review lifecycle.
type FalsePositiveReview struct {
	ID                     uuid.UUID           `json:"id"`
	TenantID               uuid.UUID           `json:"tenant_id"`
	FindingID              uuid.UUID           `json:"finding_id"`
	ActorID                *uuid.UUID          `json:"actor_id,omitempty"`
	Action                 FalsePositiveAction `json:"action"`
	Justification          string              `json:"justification"`
	EvidenceRebuttal       string              `json:"evidence_rebuttal,omitempty"`
	MaterialChangeDetected bool                `json:"material_change_detected"`
	Metadata               map[string]any      `json:"metadata"`
	CreatedAt              time.Time           `json:"created_at"`
}

// ValidateFalsePositiveDecision enforces business invariants on false-positive review submissions.
func ValidateFalsePositiveDecision(review *FalsePositiveReview) error {
	if review == nil {
		return errors.New("findings: false positive review cannot be nil")
	}
	if review.TenantID == uuid.Nil {
		return ErrTenantRequired
	}
	if review.FindingID == uuid.Nil {
		return ErrFindingIDRequired
	}
	if !validActions[review.Action] {
		return fmt.Errorf("%w: %q", ErrInvalidAction, review.Action)
	}
	if review.ActorID == nil || *review.ActorID == uuid.Nil {
		return ErrActorRequired
	}
	trimmedJustification := strings.TrimSpace(review.Justification)
	if len(trimmedJustification) < MinRationaleLength {
		return fmt.Errorf("%w: current length is %d", ErrRationaleTooShort, len(trimmedJustification))
	}
	return nil
}

// DetectMaterialChange checks whether newly submitted evidence indicates a material shift from prior evidence
// (such as altered payload hashes, new parameters, or changed response proofs).
func DetectMaterialChange(previousEvidence []normalization.Evidence, currentEvidence []normalization.Evidence) bool {
	if len(previousEvidence) == 0 && len(currentEvidence) > 0 {
		return true
	}
	if len(currentEvidence) == 0 && len(previousEvidence) > 0 {
		return false
	}

	prevChecksums := make(map[string]bool, len(previousEvidence))
	for _, pe := range previousEvidence {
		if pe.ChecksumSHA256 != "" {
			prevChecksums[pe.ChecksumSHA256] = true
		}
	}

	// If any new evidence has a checksum not present in previous evidence, it is materially changed
	for _, ce := range currentEvidence {
		if ce.ChecksumSHA256 != "" && !prevChecksums[ce.ChecksumSHA256] {
			return true
		}
	}

	return false
}

// MarkFindingFalsePositive transitions a finding to FALSE_POSITIVE, persists an immutable review record,
// and appends a corresponding timeline event.
func (r *PostgresFindingRepository) MarkFindingFalsePositive(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	actorID uuid.UUID,
	justification, rebuttal string,
	corrID uuid.UUID,
) (*FalsePositiveReview, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}

	finding, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	if CanonicalStatus(finding.Status) == StatusFalsePositive {
		return nil, ErrAlreadyFalsePositive
	}

	review := &FalsePositiveReview{
		ID:                     uuid.New(),
		TenantID:               tenantID,
		FindingID:              findingID,
		ActorID:                &actorID,
		Action:                 ActionMarkedFalsePositive,
		Justification:          justification,
		EvidenceRebuttal:       rebuttal,
		MaterialChangeDetected: false,
		Metadata:               make(map[string]any),
		CreatedAt:              time.Now().UTC(),
	}

	if err := ValidateFalsePositiveDecision(review); err != nil {
		return nil, err
	}

	// 1. Transition finding lifecycle status to FALSE_POSITIVE
	fromStatus := finding.Status
	finding.Status = StatusFalsePositive
	finding.UpdatedAt = review.CreatedAt

	const updateStatusQuery = `
		UPDATE findings
		SET status = $1, updated_at = $2
		WHERE id = $3 AND tenant_id = $4;
	`
	if _, err := r.db.Exec(ctx, updateStatusQuery, string(StatusFalsePositive), finding.UpdatedAt, findingID, tenantID); err != nil {
		return nil, fmt.Errorf("findings: update finding status to FALSE_POSITIVE failed: %w", err)
	}

	// 2. Persist false positive review record
	metaBytes, err := json.Marshal(review.Metadata)
	if err != nil {
		return nil, fmt.Errorf("findings: marshal fp review metadata: %w", err)
	}

	const insertReviewQuery = `
		INSERT INTO finding_false_positive_reviews (
			id, tenant_id, finding_id, actor_id, action, justification,
			evidence_rebuttal, material_change_detected, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	`
	if _, err := r.db.Exec(ctx, insertReviewQuery,
		review.ID,
		review.TenantID,
		review.FindingID,
		review.ActorID,
		string(review.Action),
		review.Justification,
		review.EvidenceRebuttal,
		review.MaterialChangeDetected,
		metaBytes,
		review.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("findings: insert false positive review failed: %w", err)
	}

	// 3. Record lifecycle audit event
	event := &FindingEvent{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		FromStatus:    &fromStatus,
		ToStatus:      StatusFalsePositive,
		EventType:     EventTriage,
		ActorUserID:   &actorID,
		Note:          justification,
		CorrelationID: corrID,
		CreatedAt:     review.CreatedAt,
	}
	if err := r.SaveEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("findings: save finding event failed: %w", err)
	}

	// 4. Record timeline event
	_ = r.RecordTimelineEvent(ctx, &TimelineEntry{
		ID:        uuid.New(),
		TenantID:  tenantID,
		FindingID: findingID,
		ActorID:   &actorID,
		EventType: TimelineEventFalsePositiveMarked,
		Payload: map[string]any{
			"from_status":       string(fromStatus),
			"to_status":         string(StatusFalsePositive),
			"justification":     justification,
			"evidence_rebuttal": rebuttal,
		},
		CorrelationID: corrID,
		CreatedAt:     review.CreatedAt,
	})

	return review, nil
}

// ReverseFalsePositive transitions a previously marked FALSE_POSITIVE finding back to an active state
// (e.g. REOPENED, NEW, or IN_PROGRESS), requiring an authorized rationale.
func (r *PostgresFindingRepository) ReverseFalsePositive(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
	actorID uuid.UUID,
	targetStatus FindingStatus,
	justification string,
	corrID uuid.UUID,
) (*FalsePositiveReview, error) {
	if tenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}
	if findingID == uuid.Nil {
		return nil, ErrFindingIDRequired
	}
	if targetStatus == "" {
		return nil, ErrTargetStatusRequired
	}

	finding, err := r.GetFindingByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	if CanonicalStatus(finding.Status) != StatusFalsePositive {
		return nil, ErrNotFalsePositive
	}

	if err := ValidateTransition(finding.Status, targetStatus); err != nil {
		return nil, fmt.Errorf("findings: invalid reversal transition: %w", err)
	}

	review := &FalsePositiveReview{
		ID:                     uuid.New(),
		TenantID:               tenantID,
		FindingID:              findingID,
		ActorID:                &actorID,
		Action:                 ActionReversed,
		Justification:          justification,
		MaterialChangeDetected: false,
		Metadata: map[string]any{
			"target_status": string(targetStatus),
		},
		CreatedAt: time.Now().UTC(),
	}

	if err := ValidateFalsePositiveDecision(review); err != nil {
		return nil, err
	}

	// 1. Transition finding lifecycle status
	fromStatus := finding.Status
	finding.Status = targetStatus
	finding.UpdatedAt = review.CreatedAt

	const updateStatusQuery = `
		UPDATE findings
		SET status = $1, updated_at = $2
		WHERE id = $3 AND tenant_id = $4;
	`
	if _, err := r.db.Exec(ctx, updateStatusQuery, string(targetStatus), finding.UpdatedAt, findingID, tenantID); err != nil {
		return nil, fmt.Errorf("findings: reverse finding status failed: %w", err)
	}

	// 2. Persist reversal review record
	metaBytes, err := json.Marshal(review.Metadata)
	if err != nil {
		return nil, fmt.Errorf("findings: marshal fp reversal metadata: %w", err)
	}

	const insertReviewQuery = `
		INSERT INTO finding_false_positive_reviews (
			id, tenant_id, finding_id, actor_id, action, justification,
			evidence_rebuttal, material_change_detected, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	`
	if _, err := r.db.Exec(ctx, insertReviewQuery,
		review.ID,
		review.TenantID,
		review.FindingID,
		review.ActorID,
		string(review.Action),
		review.Justification,
		review.EvidenceRebuttal,
		review.MaterialChangeDetected,
		metaBytes,
		review.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("findings: insert false positive reversal failed: %w", err)
	}

	// 3. Record lifecycle audit event
	event := &FindingEvent{
		ID:            uuid.New(),
		TenantID:      tenantID,
		FindingID:     findingID,
		FromStatus:    &fromStatus,
		ToStatus:      targetStatus,
		EventType:     EventTriage,
		ActorUserID:   &actorID,
		Note:          justification,
		CorrelationID: corrID,
		CreatedAt:     review.CreatedAt,
	}
	if err := r.SaveEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("findings: save reversal event failed: %w", err)
	}

	// 4. Record timeline event
	_ = r.RecordTimelineEvent(ctx, &TimelineEntry{
		ID:        uuid.New(),
		TenantID:  tenantID,
		FindingID: findingID,
		ActorID:   &actorID,
		EventType: TimelineEventFalsePositiveReopened,
		Payload: map[string]any{
			"from_status":   string(fromStatus),
			"to_status":     string(targetStatus),
			"justification": justification,
		},
		CorrelationID: corrID,
		CreatedAt:     review.CreatedAt,
	})

	return review, nil
}

// GetFalsePositiveReviewsByFinding retrieves all false-positive reviews and reversals for a finding.
func (r *PostgresFindingRepository) GetFalsePositiveReviewsByFinding(
	ctx context.Context,
	tenantID, findingID uuid.UUID,
) ([]*FalsePositiveReview, error) {
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
			id, tenant_id, finding_id, actor_id, action, justification,
			evidence_rebuttal, material_change_detected, metadata, created_at
		FROM finding_false_positive_reviews
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY created_at DESC;
	`
	rows, err := r.db.Query(ctx, query, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("findings: query false positive reviews failed: %w", err)
	}
	defer rows.Close()

	var reviews []*FalsePositiveReview
	for rows.Next() {
		var rev FalsePositiveReview
		var actionStr string
		var metaBytes []byte
		var rebuttal *string

		if err := rows.Scan(
			&rev.ID,
			&rev.TenantID,
			&rev.FindingID,
			&rev.ActorID,
			&actionStr,
			&rev.Justification,
			&rebuttal,
			&rev.MaterialChangeDetected,
			&metaBytes,
			&rev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("findings: scan false positive review row: %w", err)
		}

		rev.Action = FalsePositiveAction(actionStr)
		if rebuttal != nil {
			rev.EvidenceRebuttal = *rebuttal
		}
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &rev.Metadata)
		}
		if rev.Metadata == nil {
			rev.Metadata = make(map[string]any)
		}

		reviews = append(reviews, &rev)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: iterate false positive reviews: %w", err)
	}

	return reviews, nil
}
