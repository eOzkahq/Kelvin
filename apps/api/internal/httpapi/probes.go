package httpapi

import (
	"context"
	"net/http"
	"time"

	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
)

// DefaultProbeTimeout limits readiness checks to 2 seconds to prevent hanging orchestrator probes.
const DefaultProbeTimeout = 2 * time.Second

// Pinger defines the interface for checking component health (PostgreSQL, Redis, Storage).
type Pinger interface {
	Ping(ctx context.Context) error
}

// ReadyCheckers aggregates dependency pingers.
type ReadyCheckers struct {
	DB      Pinger
	Redis   Pinger
	Storage Pinger
}

type livenessData struct {
	Status string `json:"status"`
}

type readinessData struct {
	Status    string `json:"status"`
	Database  string `json:"database"`
	Broker    string `json:"broker"`
	Timestamp string `json:"timestamp"`
}

// handleHealthLive handles GET /health/live (Liveness probe).
// Returns HTTP 200 independently of external dependencies to confirm the process event loop is responsive.
func (s *Server) handleHealthLive(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, r, http.StatusOK, livenessData{
		Status: "LIVE",
	}, nil)
}

// handleHealthReady handles GET /health/ready (Readiness probe).
// Verifies connectivity to core dependencies with a strict 2s context timeout.
// Sanitizes responses to ensure zero internal hostnames, IPs, or secrets are exposed.
func (s *Server) handleHealthReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), DefaultProbeTimeout)
	defer cancel()

	now := time.Now().UTC().Format(time.RFC3339)
	dbStatus := "NOT_CONFIGURED"
	redisStatus := "NOT_CONFIGURED"
	var checkFailed bool

	if s.readyCheckers.DB != nil {
		dbStatus = "UP"
		if err := s.readyCheckers.DB.Ping(ctx); err != nil {
			dbStatus = "DOWN"
			checkFailed = true
		}
	}

	if s.readyCheckers.Redis != nil {
		redisStatus = "UP"
		if err := s.readyCheckers.Redis.Ping(ctx); err != nil {
			redisStatus = "DOWN"
			checkFailed = true
		}
	}

	if checkFailed {
		// Emit HTTP 503 Service Unavailable with sanitized problem details (RFC 7807)
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "one or more essential dependencies are unavailable",
		})
		return
	}

	WriteSuccess(w, r, http.StatusOK, readinessData{
		Status:    "READY",
		Database:  dbStatus,
		Broker:    redisStatus,
		Timestamp: now,
	}, nil)
}
