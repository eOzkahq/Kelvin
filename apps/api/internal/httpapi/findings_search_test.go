package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFindingsSearchAndDashboardEndpoints(t *testing.T) {
	tenantID := uuid.New()
	asmtID := uuid.New()
	score := 85.0

	f1 := &findings.PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-search-1",
		Title:            "Spring RCE Remote Code Execution",
		Severity:         "CRITICAL",
		Status:           findings.StatusConfirmed,
		RiskScore:        &score,
		RiskPriorityBand: findings.RiskBandCritical,
		AffectedEndpoint: "https://api.kelvin.internal/v1/user",
		ScannerData:      map[string]any{"scanner_type": "nuclei"},
		FirstSeenAt:      time.Now().UTC(),
		LastSeenAt:       time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	f2 := &findings.PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		AssessmentID:     asmtID,
		Fingerprint:      "fp-search-2",
		Title:            "Open Redirect",
		Severity:         "MEDIUM",
		Status:           findings.StatusResolved,
		AffectedEndpoint: "https://api.kelvin.internal/redirect",
		ScannerData:      map[string]any{"scanner_type": "zap"},
		FirstSeenAt:      time.Now().UTC(),
		LastSeenAt:       time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	store := &mockFindingStore{
		findings: map[uuid.UUID]*findings.PersistentFinding{
			f1.ID: f1,
			f2.ID: f2,
		},
	}

	cfg := config.Config{BodyLimitBytes: 1048576}
	srv := New(cfg, zap.NewNop())
	srv.SetFindingStore(store)
	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	t.Run("GET /api/v1/findings listing with filtering and pagination", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?severity=CRITICAL&limit=10&offset=0", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Data []findings.PersistentFinding `json:"data"`
			Meta struct {
				TotalCount int `json:"total_count"`
				Limit      int `json:"limit"`
				Offset     int `json:"offset"`
			} `json:"meta"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, 1, resp.Meta.TotalCount)
		assert.Len(t, resp.Data, 1)
		assert.Equal(t, "CRITICAL", resp.Data[0].Severity)
		assert.Equal(t, f1.ID, resp.Data[0].ID)
	})

	t.Run("GET /api/v1/findings text search", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?q=Redirect", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Data []findings.PersistentFinding `json:"data"`
			Meta struct {
				TotalCount int `json:"total_count"`
			} `json:"meta"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, 1, resp.Meta.TotalCount)
		assert.Equal(t, "Open Redirect", resp.Data[0].Title)
	})

	t.Run("GET /api/v1/findings/dashboard", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/dashboard", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Data findings.FindingDashboardMetrics `json:"data"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, 2, resp.Data.TotalFindings)
		assert.Equal(t, 1, resp.Data.OpenFindings)
		assert.Equal(t, 1, resp.Data.ResolvedFindings)
		assert.Equal(t, 1, resp.Data.SeverityBreakdown["CRITICAL"])
		assert.Equal(t, 1, resp.Data.SeverityBreakdown["MEDIUM"])
	})
}
