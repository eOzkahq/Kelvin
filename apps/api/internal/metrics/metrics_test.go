package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRegistryAndHandler(t *testing.T) {
	r := &Registry{}
	r.IncRequests()
	r.IncRequests()
	r.IncErrors()
	r.IncActiveJobs()
	r.IncCompletedJobs()

	snap := r.Snapshot()
	if snap.HTTPRequests != 2 {
		t.Errorf("expected 2 requests, got %d", snap.HTTPRequests)
	}
	if snap.HTTPErrors != 1 {
		t.Errorf("expected 1 error, got %d", snap.HTTPErrors)
	}
	if snap.ActiveJobs != 1 {
		t.Errorf("expected 1 active job, got %d", snap.ActiveJobs)
	}

	r.DecActiveJobs()
	if r.Snapshot().ActiveJobs != 0 {
		t.Errorf("expected 0 active jobs after decrement")
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", w.Code)
	}

	body := w.Body.String()
	expectedMetrics := []string{
		"kelvin_http_requests_total 2",
		"kelvin_http_errors_total 1",
		"kelvin_jobs_active 0",
		"kelvin_jobs_completed_total 1",
	}
	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("expected metric output to contain %q, body:\n%s", metric, body)
		}
	}
}

