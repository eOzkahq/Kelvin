package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/metrics"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
	"github.com/kelvin/kelvin/apps/api/pkg/job"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"go.uber.org/zap"
)

// Server assembles the routing table and the API_STANDARDS §12.1 middleware
// pipeline: Correlation → Access log → Recover → Body limit → AuthN/AuthZ
// (P2, deny-by-default RBAC per RBAC_MATRIX) → validation → handlers.
type Server struct {
	cfg           config.Config
	log           *zap.Logger
	mux           *http.ServeMux
	readyCheckers ReadyCheckers
	jobStore      jobStoreIface // nil means cancel endpoint returns 503
}

// New builds the server with all registered routes.
func New(cfg config.Config, log *zap.Logger) *Server {
	s := &Server{cfg: cfg, log: log, mux: http.NewServeMux()}
	s.routes()
	return s
}

// SetJobStore assigns the job store used by the cancel endpoint. If nil, the
// cancel endpoint returns 503.
func (s *Server) SetJobStore(store jobStoreIface) {
	s.jobStore = store
}

// jobStoreIface is the subset of job.Store used by the cancel endpoint, so
// tests can inject a mock without a database.
type jobStoreIface interface {
	Transition(ctx context.Context, id string, to job.State, workerID string) error
}

// SetReadyCheckers configures the external dependency health checkers for readiness probes.
func (s *Server) SetReadyCheckers(checkers ReadyCheckers) {
	s.readyCheckers = checkers
}

// Handler returns the fully composed middleware chain.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = middleware.BodyLimit(s.cfg.BodyLimitBytes)(h)
	h = Recover()(h)
	h = middleware.AccessLog()(h)
	h = middleware.Correlation(h)
	return h
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /health/live", s.handleHealthLive)
	s.mux.HandleFunc("GET /health/ready", s.handleHealthReady)
	s.mux.HandleFunc("GET /metrics", metrics.Default().Handler())
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/cancel", s.handleCancelAssessment)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		s.mux.Handle(method+" /api/v1/health", methodNotAllowed("GET"))
		s.mux.Handle(method+" /health/live", methodNotAllowed("GET"))
		s.mux.Handle(method+" /health/ready", methodNotAllowed("GET"))
	}
	s.mux.HandleFunc("/", s.handleNotFound)
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	WriteProblem(w, r, kelvinerrors.NewNotFound("no route matches this path"))
}

// handleCancelAssessment transitions an assessment job to CANCELLED.
// Requires the job to be in QUEUED, Validating, or RUNNING state; terminal
// states reject with 409. Returns 503 if no job store is configured.
func (s *Server) handleCancelAssessment(w http.ResponseWriter, r *http.Request) {
	if s.jobStore == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "job store not configured",
		})
		return
	}

	id := r.PathValue("id")
	if id == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_assessment_id",
			Message: "assessment id is required",
		}}))
		return
	}
	if _, err := uuid.Parse(id); err != nil {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "invalid_assessment_id",
			Message: "assessment id must be a valid UUID",
		}}))
		return
	}

	// Transition to CANCELLED; ValidateTransition rejects terminal states with
	// ErrInvalidTransition, which we map to 409 Conflict.
	if err := s.jobStore.Transition(r.Context(), id, job.Cancelled, ""); err != nil {
		if errors.Is(err, job.ErrInvalidTransition) {
			WriteProblem(w, r, kelvinerrors.NewConflict("assessment cannot be cancelled in its current state"))
			return
		}
		if errors.Is(err, job.ErrNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("assessment not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, map[string]string{"status": "cancelled", "id": id}, nil)
}

func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemMethodNotAllowed,
			Title:  "Method Not Allowed",
			Status: http.StatusMethodNotAllowed,
			Detail: "the " + strings.TrimSpace(r.Method) + " method is not supported by this resource",
		})
	}
}
