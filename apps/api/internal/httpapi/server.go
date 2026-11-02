package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/idempotency"
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
	cfg              config.Config
	log              *zap.Logger
	mux              *http.ServeMux
	readyCheckers    ReadyCheckers
	jobStore         jobStoreIface     // nil means cancel endpoint returns 503
	idempotencyStore idempotency.Store // nil means idempotency middleware is disabled
	findingStore     findingStoreIface // nil means finding endpoints return 503
	protectedRoute   func(http.Handler) http.Handler
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

// SetIdempotencyStore assigns the idempotency store used by the idempotency
// middleware on state-mutating endpoints. If nil, idempotency checks are
// disabled and requests pass through unchanged.
func (s *Server) SetIdempotencyStore(store idempotency.Store) {
	s.idempotencyStore = store
}

// SetProtectedRouteMiddleware installs authentication and authorization for data routes.
// Until configured, protected routes fail closed with 503.
func (s *Server) SetProtectedRouteMiddleware(wrap func(http.Handler) http.Handler) {
	s.protectedRoute = wrap
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

	// State-mutating endpoints are wrapped with idempotency middleware when a
	// store is configured. The middleware is a no-op for requests without an
	// Idempotency-Key header.
	var cancelHandler http.Handler = http.HandlerFunc(s.handleCancelAssessment)
	if s.idempotencyStore != nil {
		cancelHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(cancelHandler)
	}
	s.mux.Handle("POST /api/v1/assessments/{id}/cancel", s.protect(cancelHandler))

	// Finding detail retrieval endpoint (P3-08)
	s.mux.Handle("GET /api/v1/findings/{id}", s.protect(http.HandlerFunc(s.handleGetFinding)))

	// Finding status transition command endpoint (P3-10)
	var transitionHandler http.Handler = http.HandlerFunc(s.handleTransitionFinding)
	if s.idempotencyStore != nil {
		transitionHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(transitionHandler)
	}
	s.mux.Handle("POST /api/v1/findings/{id}/transition", s.protect(transitionHandler))

	// Finding activity timeline endpoint (P3-11)
	s.mux.Handle("GET /api/v1/findings/{id}/timeline", s.protect(http.HandlerFunc(s.handleGetFindingTimeline)))

	// Finding triage decision endpoint (P3-16)
	var triageHandler http.Handler = http.HandlerFunc(s.handleTriageFinding)
	if s.idempotencyStore != nil {
		triageHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(triageHandler)
	}
	s.mux.Handle("POST /api/v1/findings/{id}/triage", s.protect(triageHandler))

	// False-positive review endpoints (P3-17)
	var fpMarkHandler http.Handler = http.HandlerFunc(s.handleMarkFalsePositive)
	var fpReverseHandler http.Handler = http.HandlerFunc(s.handleReverseFalsePositive)
	if s.idempotencyStore != nil {
		fpMarkHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(fpMarkHandler)
		fpReverseHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(fpReverseHandler)
	}
	s.mux.Handle("POST /api/v1/findings/{id}/false-positive", s.protect(fpMarkHandler))
	s.mux.Handle("POST /api/v1/findings/{id}/false-positive/reverse", s.protect(fpReverseHandler))

	// Finding suppression endpoints (P3-18)
	var suppressHandler http.Handler = http.HandlerFunc(s.handleCreateSuppression)
	var unsuppressHandler http.Handler = http.HandlerFunc(s.handleRevokeSuppression)
	if s.idempotencyStore != nil {
		suppressHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(suppressHandler)
		unsuppressHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(unsuppressHandler)
	}
	s.mux.Handle("POST /api/v1/findings/{id}/suppress", s.protect(suppressHandler))
	s.mux.Handle("POST /api/v1/findings/{id}/unsuppress", s.protect(unsuppressHandler))
	s.mux.Handle("GET /api/v1/findings/{id}/suppressions", s.protect(http.HandlerFunc(s.handleGetSuppressions)))

	// Bulk finding triage endpoint (P3-19)
	var bulkTriageHandler http.Handler = http.HandlerFunc(s.handleBulkTriage)
	if s.idempotencyStore != nil {
		bulkTriageHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(bulkTriageHandler)
	}
	s.mux.Handle("POST /api/v1/findings/bulk-triage", s.protect(bulkTriageHandler))

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		s.mux.Handle(method+" /api/v1/health", methodNotAllowed("GET"))
		s.mux.Handle(method+" /health/live", methodNotAllowed("GET"))
		s.mux.Handle(method+" /health/ready", methodNotAllowed("GET"))
	}
	s.mux.HandleFunc("/", s.handleNotFound)
}

func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.protectedRoute == nil {
			WriteProblem(w, r, &kelvinerrors.API{Type: kelvinerrors.ProblemServiceUnavailable, Title: "Service Unavailable", Status: http.StatusServiceUnavailable, Detail: "authentication is not configured"})
			return
		}
		s.protectedRoute(next).ServeHTTP(w, r)
	})
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
