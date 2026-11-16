package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"crypto/sha256"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/evidence"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/apps/api/internal/idempotency"
	"github.com/kelvin/kelvin/apps/api/internal/metrics"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
	"github.com/kelvin/kelvin/apps/api/pkg/job"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/tenant"
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
	assessmentService assessmentServiceIface
	reportService    reportServiceIface
	idempotencyStore idempotency.Store // nil means idempotency middleware is disabled
	findingStore     findingStoreIface // nil means finding endpoints return 503
	evidenceSigner   *evidence.Signer
	storageProvider  any               // optional storage adapter
	authService      authServiceIface  // nil means auth endpoints return 503
	authLimiter      *auth.MemoryRateLimiter
	protectedRoute   func(http.Handler) http.Handler
}

// Compile-time check ensuring PostgresFindingRepository satisfies findingStoreIface.
var _ findingStoreIface = (*findings.PostgresFindingRepository)(nil)

// ValidateDependencies checks that all required stores are wired. In production mode,
// missing stores return an error.
func (s *Server) ValidateDependencies(isProduction bool) error {
	if !isProduction {
		return nil
	}
	if s.jobStore == nil {
		return errors.New("server: job store is required in production")
	}
	if s.findingStore == nil {
		return errors.New("server: finding store is required in production")
	}
	if s.idempotencyStore == nil {
		return errors.New("server: idempotency store is required in production")
	}
	if s.evidenceSigner == nil {
		return errors.New("server: valid evidence signing key (at least 32 bytes) is required in production")
	}
	if s.storageProvider == nil {
		return errors.New("server: storage provider is required in production")
	}
	return nil
}

// New builds the server with all registered routes.
func New(cfg config.Config, log *zap.Logger) *Server {
	s := &Server{
		cfg:         cfg,
		log:         log,
		mux:         http.NewServeMux(),
		authLimiter: auth.NewMemoryRateLimiter(60, time.Minute),
	}
	if len(cfg.Evidence.SigningKey) >= 32 && cfg.Evidence.SigningKey != "kelvin-default-evidence-signing-key-32-bytes" {
		s.evidenceSigner, _ = evidence.NewSigner([]byte(cfg.Evidence.SigningKey))
	} else if cfg.Development {
		hash := sha256.Sum256([]byte("kelvin-dev-only-ephemeral-key-" + cfg.APIVersion))
		s.evidenceSigner, _ = evidence.NewSigner(hash[:])
	}
	s.routes()
	return s
}

// SetStorageProvider assigns the storage service provider.
func (s *Server) SetStorageProvider(provider any) {
	s.storageProvider = provider
}

// SetJobStore assigns the job store used by the cancel endpoint. If nil, the
// cancel endpoint returns 503.
func (s *Server) SetJobStore(store jobStoreIface) {
	s.jobStore = store
}

// SetAssessmentService assigns the assessment service handler.
func (s *Server) SetAssessmentService(svc assessmentServiceIface) {
	s.assessmentService = svc
}

// SetReportService assigns the report service handler.
func (s *Server) SetReportService(svc reportServiceIface) {
	s.reportService = svc
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
	h = middleware.CORS(s.cfg.AllowedOrigins)(h)
	h = Recover()(h)
	h = middleware.AccessLog()(h)
	h = middleware.Correlation(h)
	return h
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /healthz", s.handleHealthLive)
	s.mux.HandleFunc("GET /readyz", s.handleHealthReady)
	s.mux.HandleFunc("GET /health/live", s.handleHealthLive)
	s.mux.HandleFunc("GET /health/ready", s.handleHealthReady)
	s.mux.HandleFunc("GET /health/db", s.handleHealthDB)
	s.mux.HandleFunc("GET /health/redis", s.handleHealthRedis)
	s.mux.HandleFunc("GET /metrics", metrics.Default().Handler())

	// Authentication endpoints
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/v1/auth/refresh", s.handleAuthRefresh)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.handleAuthLogout)
	s.mux.Handle("GET /api/v1/auth/me", s.protect(http.HandlerFunc(s.handleAuthMe)))

	// State-mutating endpoints are wrapped with idempotency middleware when a
	// store is configured. The middleware is a no-op for requests without an
	// Idempotency-Key header.
	var createAssessmentHandler http.Handler = http.HandlerFunc(s.handleCreateAssessment)
	if s.idempotencyStore != nil {
		createAssessmentHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(createAssessmentHandler)
	}
	s.mux.Handle("POST /api/v1/assessments", s.protect(createAssessmentHandler))
	s.mux.Handle("GET /api/v1/assessments", s.protect(http.HandlerFunc(s.handleListAssessments)))
	s.mux.Handle("GET /api/v1/assessments/profiles", s.protect(http.HandlerFunc(s.handleGetAssessmentProfiles)))
	s.mux.Handle("GET /api/v1/targets", s.protect(http.HandlerFunc(s.handleGetTargets)))
	s.mux.Handle("GET /api/v1/assessments/{id}", s.protect(http.HandlerFunc(s.handleGetAssessment)))

	var cancelHandler http.Handler = http.HandlerFunc(s.handleCancelAssessment)
	if s.idempotencyStore != nil {
		cancelHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(cancelHandler)
	}
	s.mux.Handle("POST /api/v1/assessments/{id}/cancel", s.protect(cancelHandler))
	// Assessment-to-assessment delta comparison (P3-35)
	s.mux.Handle("GET /api/v1/assessments/{base_id}/compare/{target_id}", s.protect(http.HandlerFunc(s.handleCompareAssessments)))

	// Report generation, listing, and signed download endpoints (Milestone 7)
	var generateReportHandler http.Handler = http.HandlerFunc(s.handleGenerateReport)
	if s.idempotencyStore != nil {
		generateReportHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(generateReportHandler)
	}
	s.mux.Handle("POST /api/v1/reports/generate", s.protect(generateReportHandler))
	s.mux.Handle("GET /api/v1/reports", s.protect(http.HandlerFunc(s.handleListReports)))
	s.mux.Handle("GET /api/v1/reports/{id}/download", s.protect(http.HandlerFunc(s.handleDownloadReport)))

	// Operational dashboard stats endpoint (Milestone 7)
	s.mux.Handle("GET /api/v1/dashboard/stats", s.protect(http.HandlerFunc(s.handleGetDashboardStats)))

	// Findings search, filtering and dashboard endpoints (P3-44)
	s.mux.Handle("GET /api/v1/findings", s.protect(http.HandlerFunc(s.handleListFindingsQuery)))
	s.mux.Handle("GET /api/v1/findings/dashboard", s.protect(http.HandlerFunc(s.handleGetFindingsDashboard)))

	// Finding detail retrieval endpoint (P3-08)
	s.mux.Handle("GET /api/v1/findings/{id}", s.protect(http.HandlerFunc(s.handleGetFinding)))
	// Finding observation timeline & assessment history (P3-34)
	s.mux.Handle("GET /api/v1/findings/{id}/observations", s.protect(http.HandlerFunc(s.handleGetFindingObservationsTimeline)))
	// Finding risk score explainability endpoint (P3-24)
	s.mux.Handle("GET /api/v1/findings/{id}/risk-explanation", s.protect(http.HandlerFunc(s.handleGetRiskExplanation)))

	// Versioned risk recalculation & history endpoints (P3-25)
	var recalcRiskHandler http.Handler = http.HandlerFunc(s.handleRecalculateFindingRisk)
	if s.idempotencyStore != nil {
		recalcRiskHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(recalcRiskHandler)
	}
	s.mux.Handle("POST /api/v1/findings/{id}/recalculate-risk", s.protect(recalcRiskHandler))
	s.mux.Handle("GET /api/v1/findings/{id}/risk-history", s.protect(http.HandlerFunc(s.handleGetFindingRiskHistory)))

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

	// Target contextual risk factors (P3-22)
	var upsertTargetContextHandler http.Handler = http.HandlerFunc(s.handleUpsertTargetRiskContext)
	if s.idempotencyStore != nil {
		upsertTargetContextHandler = idempotency.NewMiddleware(s.idempotencyStore).Wrap(upsertTargetContextHandler)
	}
	s.mux.Handle("PUT /api/v1/projects/{project_id}/targets/context", s.protect(upsertTargetContextHandler))
	s.mux.Handle("GET /api/v1/projects/{project_id}/targets/context", s.protect(http.HandlerFunc(s.handleGetTargetRiskContext)))

	// Evidence retrieval and access controls (P3-31)
	s.mux.Handle("GET /api/v1/findings/{id}/evidence", s.protect(http.HandlerFunc(s.handleListFindingEvidence)))
	s.mux.Handle("GET /api/v1/findings/{id}/evidence/{evidence_id}", s.protect(http.HandlerFunc(s.handleGetFindingEvidenceDetail)))
	s.mux.Handle("GET /api/v1/findings/{id}/evidence/{evidence_id}/download", s.protect(http.HandlerFunc(s.handleGetFindingEvidenceDownload)))

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
	if s.assessmentService != nil {
		id := r.PathValue("id")
		if id == "" {
			WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
				Field:   "id",
				Code:    "missing_assessment_id",
				Message: "assessment id is required",
			}}))
			return
		}
		tenantID, _ := tenant.ID(r.Context())
		if err := s.assessmentService.CancelAssessment(r.Context(), tenantID.String(), id); err != nil {
			if errors.Is(err, assessments.ErrAssessmentNotFound) {
				WriteProblem(w, r, kelvinerrors.NewNotFound("assessment not found"))
				return
			}
			if errors.Is(err, assessments.ErrInvalidStateTransition) {
				WriteProblem(w, r, kelvinerrors.NewConflict(err.Error()))
				return
			}
			WriteProblem(w, r, kelvinerrors.NewInternal(err))
			return
		}
		WriteSuccess(w, r, http.StatusOK, map[string]any{"success": true, "message": "assessment cancelled"}, nil)
		return
	}

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
