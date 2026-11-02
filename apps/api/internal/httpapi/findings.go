package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
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
