package httpapi

import (
	"net/http"
	"strings"

	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/metrics"
	"github.com/kelvin/kelvin/apps/api/internal/middleware"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"go.uber.org/zap"
)

// Server assembles the routing table and the API_STANDARDS §12.1 middleware
// pipeline: Correlation → Access log → Recover → Body limit → AuthN/AuthZ
// (P2, deny-by-default RBAC per RBAC_MATRIX) → validation → handlers.
type Server struct {
	cfg config.Config
	log *zap.Logger
	mux *http.ServeMux
}

// New builds the server with all registered routes.
func New(cfg config.Config, log *zap.Logger) *Server {
	s := &Server{cfg: cfg, log: log, mux: http.NewServeMux()}
	s.routes()
	return s
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
	s.mux.HandleFunc("GET /metrics", metrics.Default().Handler())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		s.mux.Handle(method+" /api/v1/health", methodNotAllowed("GET"))
	}
	s.mux.HandleFunc("/", s.handleNotFound)
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	WriteProblem(w, r, kelvinerrors.NewNotFound("no route matches this path"))
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
