package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

type findingStoreIface interface {
	GetFindingByID(ctx context.Context, tenantID, findingID uuid.UUID) (*findings.PersistentFinding, error)
	GetObservationsByFinding(ctx context.Context, tenantID, findingID uuid.UUID, limit, offset int) ([]*findings.FindingObservation, error)
}

// FindingDetailResponse encapsulates the finding record and paginated observation history.
type FindingDetailResponse struct {
	Finding      *findings.PersistentFinding    `json:"finding"`
	Observations []*findings.FindingObservation `json:"observations"`
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
