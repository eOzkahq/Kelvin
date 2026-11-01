package readiness

import (
	"encoding/json"
	"net/http"
)

// HTTPHandler returns an http.Handler serving public readiness and liveness checks (/readyz, /healthz).
// Public responses are sanitized and never expose internal file paths, image digests, or catalog structures.
func HTTPHandler(checker *Checker) http.Handler {
	mux := http.NewServeMux()

	// Public health & readiness endpoints
	publicCheck := func(w http.ResponseWriter, r *http.Request) {
		report := checker.EvaluateAll(r.Context())
		summary := checker.PublicSummary(report)

		statusCode := http.StatusOK
		if summary.Status == "down" {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(summary)
	}

	mux.HandleFunc("/healthz", publicCheck)
	mux.HandleFunc("/readyz", publicCheck)
	mux.HandleFunc("/", publicCheck)

	return mux
}

// InternalDiagnosticsHandler returns an http.Handler serving full internal diagnostic reports.
// This interface is intended strictly for authenticated internal cluster operations.
func InternalDiagnosticsHandler(checker *Checker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := checker.EvaluateAll(r.Context())

		statusCode := http.StatusOK
		if report.ApplicationStatus == StatusUnavailable {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(report)
	})
}
