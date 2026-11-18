package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/evidence"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/logging"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

type findingStoreIface interface {
	GetFindingByID(ctx context.Context, tenantID, findingID uuid.UUID) (*findings.PersistentFinding, error)
	GetObservationsByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*findings.FindingObservation, error)
	GetTimelineByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*findings.TimelineEntry, error)
	UpdateFindingStatus(ctx context.Context, tenantID, findingID uuid.UUID, newStatus findings.FindingStatus, actorUserID *uuid.UUID, note string, correlationID uuid.UUID) (*findings.PersistentFinding, *findings.FindingEvent, error)
	SaveTriageDecision(ctx context.Context, decision *findings.TriageDecision) error
	MarkFindingFalsePositive(ctx context.Context, tenantID, findingID uuid.UUID, actorID uuid.UUID, justification, rebuttal string, corrID uuid.UUID) (*findings.FalsePositiveReview, error)
	ReverseFalsePositive(ctx context.Context, tenantID, findingID uuid.UUID, actorID uuid.UUID, targetStatus findings.FindingStatus, justification string, corrID uuid.UUID) (*findings.FalsePositiveReview, error)
	GetFalsePositiveReviewsByFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]*findings.FalsePositiveReview, error)
	CreateSuppressionRule(ctx context.Context, tenantID, findingID uuid.UUID, actorID *uuid.UUID, reason string, expiresAt time.Time, corrID uuid.UUID) (*findings.SuppressionRule, error)
	RevokeSuppressionRule(ctx context.Context, tenantID, findingID uuid.UUID, actorID *uuid.UUID, revocationReason string, corrID uuid.UUID) (*findings.SuppressionRule, error)
	GetSuppressionsByFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]*findings.SuppressionRule, error)
	ExecuteBulkTriage(ctx context.Context, tenantID uuid.UUID, req *findings.BulkTriageRequest, corrID uuid.UUID) (*findings.BulkTriageResult, error)
	UpsertTargetRiskContext(ctx context.Context, trc *findings.TargetRiskContext) error
	GetTargetRiskContext(ctx context.Context, tenantID, projectID uuid.UUID, targetAsset string) (*findings.TargetRiskContext, error)
	GetRiskExplanation(ctx context.Context, tenantID, findingID uuid.UUID) (*findings.RiskExplanation, error)
	ArchiveRiskHistory(ctx context.Context, entry *findings.FindingRiskHistoryEntry) error
	GetRiskHistoryByFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]*findings.FindingRiskHistoryEntry, error)
	RecalculateFindingRisk(ctx context.Context, tenantID, findingID uuid.UUID, reason string, actorID *uuid.UUID) (*findings.RecalculateRiskResult, error)
	GetEvidenceByFindingID(ctx context.Context, tenantID, findingID uuid.UUID) ([]*evidence.EvidenceItem, error)
	GetEvidenceByID(ctx context.Context, tenantID, evidenceID uuid.UUID) (*evidence.EvidenceItem, error)
	GetObservationsByAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) ([]*findings.FindingObservation, []string, error)
	SearchFindings(ctx context.Context, q findings.FindingSearchQuery) (*findings.FindingSearchResult, error)
	GetDashboardMetrics(ctx context.Context, tenantID uuid.UUID) (*findings.FindingDashboardMetrics, error)
}

// UpsertTargetRiskContextRequest models the request payload for defining target risk attributes.
type UpsertTargetRiskContextRequest struct {
	TargetAsset         string                       `json:"target_asset"`
	Environment         findings.TargetEnvironment   `json:"environment"`
	InternetFacing      bool                         `json:"internet_facing"`
	ContainsPII         bool                         `json:"contains_pii"`
	BusinessCriticality findings.BusinessCriticality `json:"business_criticality"`
	Source              string                       `json:"source,omitempty"`
}

// TargetRiskContextResponse encapsulates target context alongside computed multipliers.
type TargetRiskContextResponse struct {
	Context             *findings.TargetRiskContext `json:"context"`
	CompositeMultiplier float64                     `json:"composite_multiplier"`
	Signals             []string                    `json:"signals"`
}

// FindingDetailResponse encapsulates the finding record and paginated observation history.
type FindingDetailResponse struct {
	Finding      *findings.PersistentFinding    `json:"finding"`
	Observations []*findings.FindingObservation `json:"observations"`
}

// TransitionFindingRequest captures requested status change and analyst reason.
type TransitionFindingRequest struct {
	TargetStatus string `json:"target_status"`
	Reason       string `json:"reason,omitempty"`
}

// TransitionFindingResponse encapsulates the outcome of a status transition.
type TransitionFindingResponse struct {
	Finding *findings.PersistentFinding `json:"finding"`
	Event   *findings.FindingEvent      `json:"event"`
}

// CreateSuppressionRequest models input to temporarily suppress a finding.
type CreateSuppressionRequest struct {
	Reason    string     `json:"reason"`
	ExpiresAt time.Time  `json:"expires_at"`
	ActorID   *uuid.UUID `json:"actor_id,omitempty"`
}

// RevokeSuppressionRequest models input to revoke a suppression rule.
type RevokeSuppressionRequest struct {
	Reason  string     `json:"reason"`
	ActorID *uuid.UUID `json:"actor_id,omitempty"`
}

// MarkFalsePositiveRequest captures the analyst review input for classifying a finding as false positive.
type MarkFalsePositiveRequest struct {
	Justification    string     `json:"justification"`
	EvidenceRebuttal string     `json:"evidence_rebuttal,omitempty"`
	ActorID          *uuid.UUID `json:"actor_id,omitempty"`
}

// ReverseFalsePositiveRequest captures the analyst reversal input.
type ReverseFalsePositiveRequest struct {
	TargetStatus  string     `json:"target_status"`
	Justification string     `json:"justification"`
	ActorID       *uuid.UUID `json:"actor_id,omitempty"`
}

// TriageFindingRequest captures an analyst's triage disposition decision.
type TriageFindingRequest struct {
	Disposition        string     `json:"disposition"`
	Scope              string     `json:"scope,omitempty"`
	Justification      string     `json:"justification"`
	ApproverID         *uuid.UUID `json:"approver_id,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	CanonicalFindingID *uuid.UUID `json:"canonical_finding_id,omitempty"`
}

// SetFindingStore assigns the finding store used by finding endpoints.
func (s *Server) SetFindingStore(store findingStoreIface) {
	s.findingStore = store
}

// handleGetFinding handles GET /api/v1/findings/{id}.
func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			if l > 100 {
				limit = 100
			} else {
				limit = l
			}
		}
	}

	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	f, err := s.findingStore.GetFindingByID(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	obs, err := s.findingStore.GetObservationsByFinding(r.Context(), tenantID, findingID, limit, offset)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}
	if obs == nil {
		obs = []*findings.FindingObservation{}
	}

	meta := map[string]any{
		"limit":  limit,
		"offset": offset,
		"count":  len(obs),
	}

	WriteSuccess(w, r, http.StatusOK, FindingDetailResponse{
		Finding:      f,
		Observations: obs,
	}, meta)
}

// handleTransitionFinding handles POST /api/v1/findings/{id}/transition.
func (s *Server) handleTransitionFinding(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var req TransitionFindingRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	targetStatusStr := strings.TrimSpace(req.TargetStatus)
	if targetStatusStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "target_status",
			Code:    "missing_target_status",
			Message: "target_status is required",
		}}))
		return
	}

	targetStatus := findings.FindingStatus(strings.ToUpper(targetStatusStr))
	canonicalTarget := findings.CanonicalStatus(targetStatus)

	// Reason requirement for sensitive transitions (FALSE_POSITIVE, ACCEPTED_RISK)
	if canonicalTarget == findings.StatusFalsePositive || canonicalTarget == findings.StatusAcceptedRisk {
		if strings.TrimSpace(req.Reason) == "" {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "reason",
				Code:    "reason_required",
				Message: "documented reason is required for sensitive status transition (" + string(canonicalTarget) + ")",
			}}))
			return
		}
	}

	corrID := logging.CorrelationFromContext(r.Context())
	var corrUUID uuid.UUID
	if parsed, err := uuid.Parse(corrID); err == nil {
		corrUUID = parsed
	} else {
		corrUUID = uuid.New()
	}

	updatedFinding, event, err := s.findingStore.UpdateFindingStatus(
		r.Context(),
		tenantID,
		findingID,
		targetStatus,
		nil,
		req.Reason,
		corrUUID,
	)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		if errors.Is(err, findings.ErrInvalidStatus) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "target_status",
				Code:    "invalid_status",
				Message: err.Error(),
			}}))
			return
		}
		if errors.Is(err, findings.ErrIllegalTransition) {
			WriteProblem(w, r, kelvinerrors.NewConflict("illegal status transition: "+err.Error()))
			return
		}
		if errors.Is(err, findings.ErrSameStatus) {
			WriteProblem(w, r, kelvinerrors.NewConflict("finding is already in status "+string(targetStatus)))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, TransitionFindingResponse{
		Finding: updatedFinding,
		Event:   event,
	}, nil)
}



// handleMarkFalsePositive handles POST /api/v1/findings/{id}/false-positive.
func (s *Server) handleMarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var req MarkFalsePositiveRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	trimmedJustification := strings.TrimSpace(req.Justification)
	if len(trimmedJustification) < findings.MinRationaleLength {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "justification",
			Code:    "rationale_too_short",
			Message: "documented justification of at least 20 characters is required to mark finding as false positive",
		}}))
		return
	}

	var actorID uuid.UUID
	if req.ActorID != nil && *req.ActorID != uuid.Nil {
		actorID = *req.ActorID
	} else {
		actorID = uuid.New()
	}

	corrID := logging.CorrelationFromContext(r.Context())
	var corrUUID uuid.UUID
	if parsed, err := uuid.Parse(corrID); err == nil {
		corrUUID = parsed
	} else {
		corrUUID = uuid.New()
	}

	review, err := s.findingStore.MarkFindingFalsePositive(
		r.Context(),
		tenantID,
		findingID,
		actorID,
		req.Justification,
		req.EvidenceRebuttal,
		corrUUID,
	)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		if errors.Is(err, findings.ErrAlreadyFalsePositive) {
			WriteProblem(w, r, kelvinerrors.NewConflict("finding is already marked as false positive"))
			return
		}
		if errors.Is(err, findings.ErrRationaleTooShort) || errors.Is(err, findings.ErrActorRequired) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "false_positive",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, review, nil)
}

// handleReverseFalsePositive handles POST /api/v1/findings/{id}/false-positive/reverse.
func (s *Server) handleReverseFalsePositive(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var req ReverseFalsePositiveRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	targetStatusStr := strings.TrimSpace(req.TargetStatus)
	if targetStatusStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "target_status",
			Code:    "missing_target_status",
			Message: "target_status is required for false-positive reversal",
		}}))
		return
	}

	targetStatus := findings.FindingStatus(strings.ToUpper(targetStatusStr))

	trimmedJustification := strings.TrimSpace(req.Justification)
	if len(trimmedJustification) < findings.MinRationaleLength {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "justification",
			Code:    "rationale_too_short",
			Message: "documented justification of at least 20 characters is required for false-positive reversal",
		}}))
		return
	}

	var actorID uuid.UUID
	if req.ActorID != nil && *req.ActorID != uuid.Nil {
		actorID = *req.ActorID
	} else {
		actorID = uuid.New()
	}

	corrID := logging.CorrelationFromContext(r.Context())
	var corrUUID uuid.UUID
	if parsed, err := uuid.Parse(corrID); err == nil {
		corrUUID = parsed
	} else {
		corrUUID = uuid.New()
	}

	review, err := s.findingStore.ReverseFalsePositive(
		r.Context(),
		tenantID,
		findingID,
		actorID,
		targetStatus,
		req.Justification,
		corrUUID,
	)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		if errors.Is(err, findings.ErrNotFalsePositive) {
			WriteProblem(w, r, kelvinerrors.NewConflict("finding is not currently marked as false positive"))
			return
		}
		if errors.Is(err, findings.ErrIllegalTransition) {
			WriteProblem(w, r, kelvinerrors.NewConflict("illegal reversal transition: "+err.Error()))
			return
		}
		if errors.Is(err, findings.ErrRationaleTooShort) || errors.Is(err, findings.ErrTargetStatusRequired) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "reversal",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, review, nil)
}

// handleCreateSuppression handles POST /api/v1/findings/{id}/suppress.
func (s *Server) handleCreateSuppression(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var req CreateSuppressionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	if strings.TrimSpace(req.Reason) == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "reason",
			Code:    "reason_required",
			Message: "documented reason is required for suppression",
		}}))
		return
	}

	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(time.Now().UTC()) {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "expires_at",
			Code:    "expiry_must_be_future",
			Message: "suppression expiry timestamp must be in the future",
		}}))
		return
	}

	corrID := logging.CorrelationFromContext(r.Context())
	var corrUUID uuid.UUID
	if parsed, err := uuid.Parse(corrID); err == nil {
		corrUUID = parsed
	} else {
		corrUUID = uuid.New()
	}

	rule, err := s.findingStore.CreateSuppressionRule(
		r.Context(),
		tenantID,
		findingID,
		req.ActorID,
		req.Reason,
		req.ExpiresAt,
		corrUUID,
	)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		if errors.Is(err, findings.ErrSuppressionAlreadyActive) {
			WriteProblem(w, r, kelvinerrors.NewConflict("finding is already under an active suppression rule"))
			return
		}
		if errors.Is(err, findings.ErrSuppressionReasonRequired) || errors.Is(err, findings.ErrSuppressionExpiryRequired) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "suppression",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusCreated, rule, nil)
}

// handleRevokeSuppression handles POST /api/v1/findings/{id}/unsuppress.
func (s *Server) handleRevokeSuppression(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var req RevokeSuppressionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	if strings.TrimSpace(req.Reason) == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "reason",
			Code:    "reason_required",
			Message: "reason is required to revoke suppression",
		}}))
		return
	}

	corrID := logging.CorrelationFromContext(r.Context())
	var corrUUID uuid.UUID
	if parsed, err := uuid.Parse(corrID); err == nil {
		corrUUID = parsed
	} else {
		corrUUID = uuid.New()
	}

	rule, err := s.findingStore.RevokeSuppressionRule(
		r.Context(),
		tenantID,
		findingID,
		req.ActorID,
		req.Reason,
		corrUUID,
	)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) || errors.Is(err, findings.ErrSuppressionNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("active suppression rule not found"))
			return
		}
		if errors.Is(err, findings.ErrRevocationReasonRequired) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "reason",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, rule, nil)
}

// handleGetSuppressions handles GET /api/v1/findings/{id}/suppressions.
func (s *Server) handleGetSuppressions(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	rules, err := s.findingStore.GetSuppressionsByFinding(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	meta := map[string]any{
		"count": len(rules),
		"total": len(rules),
	}

	WriteSuccess(w, r, http.StatusOK, rules, meta)
}

// handleBulkTriage handles POST /api/v1/findings/bulk-triage.
func (s *Server) handleBulkTriage(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	var req findings.BulkTriageRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	corrID := logging.CorrelationFromContext(r.Context())
	var corrUUID uuid.UUID
	if parsed, err := uuid.Parse(corrID); err == nil {
		corrUUID = parsed
	} else {
		corrUUID = uuid.New()
	}

	result, err := s.findingStore.ExecuteBulkTriage(r.Context(), tenantID, &req, corrUUID)
	if err != nil {
		if errors.Is(err, findings.ErrBulkBatchEmpty) ||
			errors.Is(err, findings.ErrBulkBatchLimitExceeded) ||
			errors.Is(err, findings.ErrInvalidBulkAction) ||
			errors.Is(err, findings.ErrTargetStatusRequired) ||
			errors.Is(err, findings.ErrBulkReasonRequired) ||
			errors.Is(err, findings.ErrSuppressionReasonRequired) ||
			errors.Is(err, findings.ErrSuppressionExpiryRequired) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "bulk_triage",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, result, nil)
}


// handleUpsertTargetRiskContext handles PUT /api/v1/projects/{project_id}/targets/context.
func (s *Server) handleUpsertTargetRiskContext(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	projStr := r.PathValue("project_id")
	if projStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "project_id",
			Code:    "missing_project_id",
			Message: "project id is required",
		}}))
		return
	}

	projectID, err := uuid.Parse(projStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "project_id",
			Code:    "invalid_project_id",
			Message: "project id must be a valid UUID",
		}}))
		return
	}

	var req UpsertTargetRiskContextRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	trc := &findings.TargetRiskContext{
		TenantID:            tenantID,
		ProjectID:           projectID,
		TargetAsset:         req.TargetAsset,
		Environment:         req.Environment,
		InternetFacing:      req.InternetFacing,
		ContainsPII:         req.ContainsPII,
		BusinessCriticality: req.BusinessCriticality,
		Source:              req.Source,
	}

	if err := s.findingStore.UpsertTargetRiskContext(r.Context(), trc); err != nil {
		if errors.Is(err, findings.ErrTargetAssetRequired) ||
			errors.Is(err, findings.ErrInvalidEnvironment) ||
			errors.Is(err, findings.ErrInvalidCriticality) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "context",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	mult, signals := findings.CalculateContextualMultiplier(trc)
	resp := TargetRiskContextResponse{
		Context:             trc,
		CompositeMultiplier: mult,
		Signals:             signals,
	}

	WriteSuccess(w, r, http.StatusOK, resp, nil)
}

// handleGetTargetRiskContext handles GET /api/v1/projects/{project_id}/targets/context.
func (s *Server) handleGetTargetRiskContext(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	projStr := r.PathValue("project_id")
	if projStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "project_id",
			Code:    "missing_project_id",
			Message: "project id is required",
		}}))
		return
	}

	projectID, err := uuid.Parse(projStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "project_id",
			Code:    "invalid_project_id",
			Message: "project id must be a valid UUID",
		}}))
		return
	}

	targetAsset := r.URL.Query().Get("target_asset")
	if strings.TrimSpace(targetAsset) == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "target_asset",
			Code:    "target_asset_required",
			Message: "target_asset query parameter is required",
		}}))
		return
	}

	trc, err := s.findingStore.GetTargetRiskContext(r.Context(), tenantID, projectID, targetAsset)
	if err != nil {
		if errors.Is(err, findings.ErrTargetRiskContextNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("target risk context not found"))
			return
		}
		if errors.Is(err, findings.ErrTargetAssetRequired) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "target_asset",
				Code:    "invalid_target_asset",
				Message: err.Error(),
			}}))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	mult, signals := findings.CalculateContextualMultiplier(trc)
	resp := TargetRiskContextResponse{
		Context:             trc,
		CompositeMultiplier: mult,
		Signals:             signals,
	}

	WriteSuccess(w, r, http.StatusOK, resp, nil)
}


// handleGetRiskExplanation handles GET /api/v1/findings/{id}/risk-explanation.
func (s *Server) handleGetRiskExplanation(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	explanation, err := s.findingStore.GetRiskExplanation(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, explanation, nil)
}

// handleGetFindingTimeline handles GET /api/v1/findings/{id}/timeline.
func (s *Server) handleGetFindingTimeline(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			if l > 100 {
				l = 100
			}
			limit = l
		}
	}

	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	timeline, err := s.findingStore.GetTimelineByFinding(r.Context(), tenantID, findingID, limit, offset)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	meta := map[string]any{
		"limit":  limit,
		"offset": offset,
		"count":  len(timeline),
	}

	WriteSuccess(w, r, http.StatusOK, timeline, meta)
}

// handleTriageFinding handles POST /api/v1/findings/{id}/triage.
func (s *Server) handleTriageFinding(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var req TriageFindingRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	decision := &findings.TriageDecision{
		TenantID:           tenantID,
		FindingID:          findingID,
		Disposition:        findings.TriageDisposition(strings.ToUpper(strings.TrimSpace(req.Disposition))),
		Scope:              findings.TriageScope(strings.ToUpper(strings.TrimSpace(req.Scope))),
		Justification:      req.Justification,
		ApproverID:         req.ApproverID,
		ExpiresAt:          req.ExpiresAt,
		CanonicalFindingID: req.CanonicalFindingID,
	}

	if err := s.findingStore.SaveTriageDecision(r.Context(), decision); err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		if errors.Is(err, findings.ErrInvalidDisposition) ||
			errors.Is(err, findings.ErrInvalidScope) ||
			errors.Is(err, findings.ErrJustificationRequired) ||
			errors.Is(err, findings.ErrExpiryRequired) ||
			errors.Is(err, findings.ErrCanonicalIDRequired) ||
			errors.Is(err, findings.ErrSelfReferentialDuplicate) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "triage",
				Code:    "validation_error",
				Message: err.Error(),
			}}))
			return
		}
		if errors.Is(err, findings.ErrIllegalTransition) {
			WriteProblem(w, r, kelvinerrors.NewConflict("illegal status transition for triage disposition: "+err.Error()))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, map[string]any{
		"disposition": decision.Disposition,
		"finding_id":  decision.FindingID,
		"status":      "triage_applied",
	}, nil)
}


// RecalculateRiskPayload captures optional reason and analyst override for recalculating risk.
type RecalculateRiskPayload struct {
	Reason  string     `json:"reason,omitempty"`
	ActorID *uuid.UUID `json:"actor_id,omitempty"`
}

// handleRecalculateFindingRisk handles POST /api/v1/findings/{id}/recalculate-risk.
func (s *Server) handleRecalculateFindingRisk(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	var payload RecalculateRiskPayload
	if r.Body != nil && r.ContentLength > 0 {
		_ = DecodeJSON(w, r, &payload)
	}

	result, err := s.findingStore.RecalculateFindingRisk(r.Context(), tenantID, findingID, payload.Reason, payload.ActorID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, result, nil)
}

// handleGetFindingRiskHistory handles GET /api/v1/findings/{id}/risk-history.
func (s *Server) handleGetFindingRiskHistory(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	history, err := s.findingStore.GetRiskHistoryByFinding(r.Context(), tenantID, findingID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	meta := map[string]any{
		"count": len(history),
	}
	WriteSuccess(w, r, http.StatusOK, history, meta)
}


// EvidenceSummaryResponse encapsulates metadata of an evidence item for list views.
type EvidenceSummaryResponse struct {
	ID              string                   `json:"id"`
	FindingID       string                   `json:"finding_id"`
	EvidenceType    evidence.EvidenceType    `json:"evidence_type"`
	ContentType     string                   `json:"content_type"`
	SizeBytes       int64                    `json:"size_bytes"`
	ChecksumSHA256  string                   `json:"checksum_sha256"`
	RedactionStatus evidence.RedactionStatus `json:"redaction_status"`
	CreatedAt       time.Time                `json:"created_at"`
}

// EvidenceDownloadResponse returns short-lived pre-signed download metadata.
type EvidenceDownloadResponse struct {
	EvidenceID       string `json:"evidence_id"`
	DownloadURL      string `json:"download_url"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
	ContentType      string `json:"content_type"`
	SizeBytes        int64  `json:"size_bytes"`
}

// handleListFindingEvidence handles GET /api/v1/findings/{id}/evidence.
func (s *Server) handleListFindingEvidence(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	// Authorize finding exists in tenant
	_, err = s.findingStore.GetFindingByID(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	items, err := s.findingStore.GetEvidenceByFindingID(r.Context(), tenantID, findingID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	summaries := make([]EvidenceSummaryResponse, 0, len(items))
	for _, it := range items {
		fID := findingID.String()
		if it.FindingID != nil {
			fID = *it.FindingID
		}
		summaries = append(summaries, EvidenceSummaryResponse{
			ID:              it.ID,
			FindingID:       fID,
			EvidenceType:    it.EvidenceType,
			ContentType:     it.ContentType,
			SizeBytes:       it.SizeBytes,
			ChecksumSHA256:  it.ChecksumSHA256,
			RedactionStatus: it.RedactionStatus,
			CreatedAt:       it.CreatedAt,
		})
	}

	meta := map[string]any{
		"count": len(summaries),
	}
	WriteSuccess(w, r, http.StatusOK, summaries, meta)
}

// handleGetFindingEvidenceDetail handles GET /api/v1/findings/{id}/evidence/{evidence_id}.
func (s *Server) handleGetFindingEvidenceDetail(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	findingID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	evidenceID, err := uuid.Parse(r.PathValue("evidence_id"))
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "evidence_id",
			Code:    "invalid_evidence_id",
			Message: "evidence id must be a valid UUID",
		}}))
		return
	}

	// 1. Authorize finding ownership
	_, err = s.findingStore.GetFindingByID(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	// 2. Fetch evidence item
	item, err := s.findingStore.GetEvidenceByID(r.Context(), tenantID, evidenceID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewNotFound("evidence not found"))
		return
	}

	// 3. Verify linkage to finding
	if item.FindingID != nil && *item.FindingID != findingID.String() {
		WriteProblem(w, r, kelvinerrors.NewNotFound("evidence not found for this finding"))
		return
	}

	// 4. Transform into sanitized presentation envelope
	sanitizer := evidence.NewSanitizerService()
	envelope, err := sanitizer.PreparePresentationEnvelope(item, false, nil)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	WriteSuccess(w, r, http.StatusOK, envelope, nil)
}

// handleGetFindingEvidenceDownload handles GET /api/v1/findings/{id}/evidence/{evidence_id}/download.
func (s *Server) handleGetFindingEvidenceDownload(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	findingID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	evidenceID, err := uuid.Parse(r.PathValue("evidence_id"))
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "evidence_id",
			Code:    "invalid_evidence_id",
			Message: "evidence id must be a valid UUID",
		}}))
		return
	}

	// 1. Authorize finding ownership
	_, err = s.findingStore.GetFindingByID(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	// 2. Fetch evidence item
	item, err := s.findingStore.GetEvidenceByID(r.Context(), tenantID, evidenceID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewNotFound("evidence not found"))
		return
	}

	if item.FindingID != nil && *item.FindingID != findingID.String() {
		WriteProblem(w, r, kelvinerrors.NewNotFound("evidence not found for this finding"))
		return
	}

	// 3. Verify safe MIME type
	if !evidence.IsSafeMimeType(item.ContentType) {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "content_type",
			Code:    "disallowed_content_type",
			Message: "evidence content type is not permitted for download",
		}}))
		return
	}

	// 4. Generate 5-minute pre-signed URL (300 seconds)
	ttl := 300 * time.Second
	baseURL := "/api/v1/evidence/" + evidenceID.String() + "/download"
	signedURL, err := s.evidenceSigner.SignDownloadURL(evidenceID.String(), tenantID.String(), ttl, baseURL)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Content-Disposition", "attachment; filename=\"evidence-" + evidenceID.String() + ".txt\"")

	resp := EvidenceDownloadResponse{
		EvidenceID:       evidenceID.String(),
		DownloadURL:      signedURL,
		ExpiresInSeconds: 300,
		ContentType:      item.ContentType,
		SizeBytes:        item.SizeBytes,
	}

	WriteSuccess(w, r, http.StatusOK, resp, nil)
}


// handleGetFindingObservationsTimeline handles GET /api/v1/findings/{id}/observations.
func (s *Server) handleGetFindingObservationsTimeline(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_finding_id",
			Message: "finding id is required",
		}}))
		return
	}

	findingID, err := uuid.Parse(idStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_finding_id",
			Message: "finding id must be a valid UUID",
		}}))
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			if l > 100 {
				limit = 100
			} else {
				limit = l
			}
		}
	}

	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	f, err := s.findingStore.GetFindingByID(r.Context(), tenantID, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("finding not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	obs, err := s.findingStore.GetObservationsByFinding(r.Context(), tenantID, findingID, limit, offset)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	timeline := findings.BuildObservationTimeline(f, obs)

	meta := map[string]any{
		"limit":  limit,
		"offset": offset,
		"count":  len(timeline.Timeline),
	}

	WriteSuccess(w, r, http.StatusOK, timeline, meta)
}


// handleCompareAssessments handles GET /api/v1/assessments/{base_id}/compare/{target_id}.
func (s *Server) handleCompareAssessments(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	baseIDStr := r.PathValue("base_id")
	targetIDStr := r.PathValue("target_id")

	baseID, err := uuid.Parse(baseIDStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "base_id",
			Code:    "invalid_base_id",
			Message: "base_id must be a valid UUID",
		}}))
		return
	}

	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "target_id",
			Code:    "invalid_target_id",
			Message: "target_id must be a valid UUID",
		}}))
		return
	}

	baseObs, baseScanners, err := s.findingStore.GetObservationsByAssessment(r.Context(), tenantID, baseID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewNotFound("base assessment not found"))
		return
	}

	targetObs, targetScanners, err := s.findingStore.GetObservationsByAssessment(r.Context(), tenantID, targetID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewNotFound("target assessment not found"))
		return
	}

	comparison, err := findings.CompareAssessments(tenantID, baseID, targetID, baseObs, targetObs, baseScanners, targetScanners)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, comparison, nil)
}


// handleListFindingsQuery handles GET /api/v1/findings.
func (s *Server) handleListFindingsQuery(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil {
			if l > 100 {
				limit = 100
			} else if l > 0 {
				limit = l
			}
		}
	}

	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	var asmtIDPtr *uuid.UUID
	if asmtStr := r.URL.Query().Get("assessment_id"); asmtStr != "" {
		if uid, err := uuid.Parse(asmtStr); err == nil {
			asmtIDPtr = &uid
		}
	}

	var isSuppPtr *bool
	if suppStr := r.URL.Query().Get("is_suppressed"); suppStr != "" {
		if b, err := strconv.ParseBool(suppStr); err == nil {
			isSuppPtr = &b
		}
	}

	q := findings.FindingSearchQuery{
		TenantID:     tenantID,
		Query:        r.URL.Query().Get("q"),
		Severity:     r.URL.Query().Get("severity"),
		Status:       findings.FindingStatus(r.URL.Query().Get("status")),
		RiskPriority: r.URL.Query().Get("risk_priority"),
		Scanner:      r.URL.Query().Get("scanner"),
		Target:       r.URL.Query().Get("target"),
		AssessmentID: asmtIDPtr,
		IsSuppressed: isSuppPtr,
		SortBy:       r.URL.Query().Get("sort_by"),
		SortOrder:    r.URL.Query().Get("sort_order"),
		Limit:        limit,
		Offset:       offset,
	}

	res, err := s.findingStore.SearchFindings(r.Context(), q)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	items := res.Items
	if items == nil {
		items = make([]*findings.PersistentFinding, 0)
	}

	meta := map[string]any{
		"limit":       res.Limit,
		"offset":      res.Offset,
		"total_count": res.TotalCount,
	}

	WriteSuccess(w, r, http.StatusOK, items, meta)
}

// handleGetFindingsDashboard handles GET /api/v1/findings/dashboard.
func (s *Server) handleGetFindingsDashboard(w http.ResponseWriter, r *http.Request) {
	if s.findingStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "finding store not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	metrics, err := s.findingStore.GetDashboardMetrics(r.Context(), tenantID)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, metrics, nil)
}
