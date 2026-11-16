package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

type assessmentServiceIface interface {
	CreateAssessment(ctx context.Context, tenantID, userID string, input assessments.CreateAssessmentInput) (*assessments.AssessmentRecord, error)
	GetAssessment(ctx context.Context, tenantID, id string) (*assessments.AssessmentDetail, error)
	ListAssessments(ctx context.Context, tenantID string, filter assessments.AssessmentFilter) ([]assessments.AssessmentRecord, int, error)
	CancelAssessment(ctx context.Context, tenantID, id string) error
	GetProfiles(ctx context.Context, tenantID string) ([]assessments.ScanProfile, error)
	GetTargets(ctx context.Context, tenantID string) ([]assessments.TargetOption, error)
}

func (s *Server) handleCreateAssessment(w http.ResponseWriter, r *http.Request) {
	if s.assessmentService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "assessment service is not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	var req assessments.CreateAssessmentInput
	if !DecodeJSON(w, r, &req) {
		return
	}

	record, err := s.assessmentService.CreateAssessment(r.Context(), tenantID.String(), "", req)
	if err != nil {
		if errors.Is(err, assessments.ErrCanaryTargetProhibited) {
			WriteProblem(w, r, &kelvinerrors.API{
				Type:   kelvinerrors.ProblemForbidden,
				Title:  "Canary Target Policy Violation",
				Status: http.StatusForbidden,
				Detail: err.Error(),
			})
			return
		}
		if errors.Is(err, assessments.ErrScopeNotConfirmed) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "authorizedScopeConfirmed",
				Code:    "scope_not_confirmed",
				Message: "authorized scope confirmation is required before scanning",
			}}))
			return
		}
		if errors.Is(err, assessments.ErrInvalidTarget) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "targetAddress",
				Code:    "invalid_target",
				Message: "target address is required and cannot be empty",
			}}))
			return
		}
		if errors.Is(err, assessments.ErrInvalidProfile) {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "profileId",
				Code:    "invalid_profile",
				Message: "scan profile is invalid or not approved",
			}}))
			return
		}

		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusCreated, map[string]any{
		"id": record.ID,
	}, nil)
}

func (s *Server) handleListAssessments(w http.ResponseWriter, r *http.Request) {
	if s.assessmentService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "assessment service is not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	filter := assessments.AssessmentFilter{
		Status:    r.URL.Query().Get("status"),
		ProfileID: r.URL.Query().Get("profile_id"),
		Search:    r.URL.Query().Get("search"),
		Limit:     limit,
		Offset:    offset,
	}

	records, total, err := s.assessmentService.ListAssessments(r.Context(), tenantID.String(), filter)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	meta := map[string]any{
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}

	WriteSuccess(w, r, http.StatusOK, records, meta)
}

func (s *Server) handleGetAssessment(w http.ResponseWriter, r *http.Request) {
	if s.assessmentService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "assessment service is not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	id := r.PathValue("id")
	if id == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_id",
			Message: "assessment ID is required",
		}}))
		return
	}

	detail, err := s.assessmentService.GetAssessment(r.Context(), tenantID.String(), id)
	if err != nil {
		if errors.Is(err, assessments.ErrAssessmentNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("assessment not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, detail, nil)
}

func (s *Server) handleGetAssessmentProfiles(w http.ResponseWriter, r *http.Request) {
	if s.assessmentService == nil {
		// Return standard default profiles even if assessment service is offline
		WriteSuccess(w, r, http.StatusOK, assessments.DefaultProfiles, nil)
		return
	}

	tenantID, _ := tenant.ID(r.Context())
	tIDStr := ""
	if tenantID != uuid.Nil {
		tIDStr = tenantID.String()
	}

	profiles, err := s.assessmentService.GetProfiles(r.Context(), tIDStr)
	if err != nil {
		WriteSuccess(w, r, http.StatusOK, assessments.DefaultProfiles, nil)
		return
	}

	WriteSuccess(w, r, http.StatusOK, profiles, nil)
}

func (s *Server) handleGetTargets(w http.ResponseWriter, r *http.Request) {
	if s.assessmentService == nil {
		// Return standard canary targets even if assessment service is offline
		WriteSuccess(w, r, http.StatusOK, assessments.DefaultTargets, nil)
		return
	}

	tenantID, _ := tenant.ID(r.Context())
	tIDStr := ""
	if tenantID != uuid.Nil {
		tIDStr = tenantID.String()
	}

	targets, err := s.assessmentService.GetTargets(r.Context(), tIDStr)
	if err != nil {
		WriteSuccess(w, r, http.StatusOK, assessments.DefaultTargets, nil)
		return
	}

	WriteSuccess(w, r, http.StatusOK, targets, nil)
}
