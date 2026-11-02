package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/evidence"
	"github.com/kelvin/kelvin/apps/api/internal/findings"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

type mockEvidenceStore struct {
	findingStore *mockFindingStore
}

func setupEvidenceTestServer(t *testing.T) (*Server, *mockFindingStore, uuid.UUID) {
	t.Helper()
	cfg := config.Config{}
	cfg.Evidence.SigningKey = "0123456789abcdef0123456789abcdef" // 32 bytes
	cfg.Evidence.SignedURLTTLSeconds = 300

	srv := New(cfg, zap.NewNop())
	tenantID := uuid.New()

	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := tenant.WithID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	store := &mockFindingStore{
		findings:          make(map[uuid.UUID]*findings.PersistentFinding),
		evidenceByFinding: make(map[uuid.UUID][]*evidence.EvidenceItem),
		evidenceByID:      make(map[uuid.UUID]*evidence.EvidenceItem),
	}
	srv.SetFindingStore(store)

	return srv, store, tenantID
}

func TestHandleListFindingEvidence(t *testing.T) {
	srv, store, tenantID := setupEvidenceTestServer(t)

	findingID := uuid.New()
	store.findings[findingID] = &findings.PersistentFinding{
		ID:       findingID,
		TenantID: tenantID,
		Title:    "SQL Injection in Search",
	}

	ev1ID := uuid.New()
	ev2ID := uuid.New()
	fidStr := findingID.String()

	ev1 := &evidence.EvidenceItem{
		ID:              ev1ID.String(),
		TenantID:        tenantID.String(),
		FindingID:       &fidStr,
		EvidenceType:    evidence.TypeHTTPObservation,
		ContentType:     "text/plain",
		SizeBytes:       256,
		ChecksumSHA256:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		RedactionStatus: evidence.RedactionSanitizedPresentation,
		CreatedAt:       time.Now().UTC(),
	}
	ev2 := &evidence.EvidenceItem{
		ID:              ev2ID.String(),
		TenantID:        tenantID.String(),
		FindingID:       &fidStr,
		EvidenceType:    evidence.TypeSecurityHeaderDiff,
		ContentType:     "text/plain",
		SizeBytes:       128,
		ChecksumSHA256:  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		RedactionStatus: evidence.RedactionUnredactedInternal,
		CreatedAt:       time.Now().UTC(),
	}

	store.evidenceByFinding[findingID] = []*evidence.EvidenceItem{ev1, ev2}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/evidence", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []EvidenceSummaryResponse `json:"data"`
		Meta map[string]any            `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)
	assert.Equal(t, 2, int(resp.Meta["count"].(float64)))
	assert.Equal(t, ev1ID.String(), resp.Data[0].ID)
	assert.Equal(t, evidence.TypeHTTPObservation, resp.Data[0].EvidenceType)
}

func TestHandleGetFindingEvidenceDetail(t *testing.T) {
	srv, store, tenantID := setupEvidenceTestServer(t)

	findingID := uuid.New()
	store.findings[findingID] = &findings.PersistentFinding{
		ID:       findingID,
		TenantID: tenantID,
		Title:    "Hardcoded Token",
	}

	evID := uuid.New()
	fidStr := findingID.String()
	rawTraffic := "GET /admin HTTP/1.1\r\nAuthorization: Bearer secret-token-xyz\r\n\r\n200 OK"

	ev := &evidence.EvidenceItem{
		ID:               evID.String(),
		TenantID:         tenantID.String(),
		FindingID:        &fidStr,
		EvidenceType:     evidence.TypeHTTPObservation,
		ContentType:      "text/plain",
		InlineContent:    rawTraffic,
		SizeBytes:        int64(len(rawTraffic)),
		ChecksumSHA256:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		RedactionStatus:  evidence.RedactionUnredactedInternal,
		SensitivityLevel: evidence.SensitivityInternal,
		CreatedAt:        time.Now().UTC(),
	}

	store.evidenceByID[evID] = ev

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/evidence/"+evID.String(), nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Check response headers
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "default-src 'none'", rec.Header().Get("Content-Security-Policy"))

	var resp struct {
		Data evidence.SanitizedEvidenceEnvelope `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, evID.String(), resp.Data.EvidenceID)
	assert.False(t, resp.Data.IsUnredactedRaw)
	// Secret token must be redacted
	assert.NotContains(t, resp.Data.SanitizedContent, "secret-token-xyz")
	assert.Contains(t, resp.Data.SanitizedContent, evidence.MaskAuthToken)
}

func TestHandleGetFindingEvidenceDownload(t *testing.T) {
	srv, store, tenantID := setupEvidenceTestServer(t)

	findingID := uuid.New()
	store.findings[findingID] = &findings.PersistentFinding{
		ID:       findingID,
		TenantID: tenantID,
		Title:    "Information Disclosure",
	}

	evID := uuid.New()
	fidStr := findingID.String()
	ev := &evidence.EvidenceItem{
		ID:              evID.String(),
		TenantID:        tenantID.String(),
		FindingID:       &fidStr,
		EvidenceType:    evidence.TypeHTTPObservation,
		ContentType:     "text/plain",
		SizeBytes:       512,
		ChecksumSHA256:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		RedactionStatus: evidence.RedactionSanitizedPresentation,
		CreatedAt:       time.Now().UTC(),
	}

	store.evidenceByID[evID] = ev

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/evidence/"+evID.String()+"/download", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "attachment; filename=\"evidence-"+evID.String()+".txt\"")

	var resp struct {
		Data EvidenceDownloadResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, evID.String(), resp.Data.EvidenceID)
	assert.Equal(t, 300, resp.Data.ExpiresInSeconds)
	assert.Contains(t, resp.Data.DownloadURL, "/api/v1/evidence/"+evID.String()+"/download?expires=")
	assert.Contains(t, resp.Data.DownloadURL, "signature=")
}

func TestHandleEvidence_NotFoundAndCrossTenantRejection(t *testing.T) {
	srv, store, tenantID := setupEvidenceTestServer(t)

	findingID := uuid.New()
	store.findings[findingID] = &findings.PersistentFinding{
		ID:       findingID,
		TenantID: tenantID,
		Title:    "Valid Finding",
	}

	// 1. Non-existent finding returns 404
	missingFinding := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+missingFinding.String()+"/evidence", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// 2. Evidence belonging to different finding returns 404
	otherFindingID := uuid.New().String()
	evID := uuid.New()
	store.evidenceByID[evID] = &evidence.EvidenceItem{
		ID:          evID.String(),
		TenantID:    tenantID.String(),
		FindingID:   &otherFindingID,
		ContentType: "text/plain",
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/evidence/"+evID.String(), nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
