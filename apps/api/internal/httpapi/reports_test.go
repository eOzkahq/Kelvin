package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	"github.com/kelvin/kelvin/apps/api/internal/config"
	"github.com/kelvin/kelvin/apps/api/internal/httpapi"
	"github.com/kelvin/kelvin/packages/common/tenant"
	"go.uber.org/zap"
)

func setupReportTestServer(t *testing.T) (*httpapi.Server, *httpapi.BuiltinReportService) {
	t.Helper()
	cfg := config.Config{
		Development:    true,
		BodyLimitBytes: 1 << 20,
	}
	log := zap.NewNop()
	srv := httpapi.New(cfg, log)

	repo := assessments.NewMemoryRepository()
	repSvc := httpapi.NewBuiltinReportService(repo, []byte("test-signing-key-at-least-32-bytes-long"))
	srv.SetReportService(repSvc)

	srv.SetProtectedRouteMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if _, err := tenant.ID(ctx); err != nil {
				tenantID := uuid.New()
				ctx, _ = tenant.WithID(ctx, tenantID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	return srv, repSvc
}

func TestHTTP_GenerateAndDownloadReport(t *testing.T) {
	srv, _ := setupReportTestServer(t)
	tenantID := uuid.New()
	asmtID := uuid.New().String()
	handler := srv.Handler()

	// 1. POST /api/v1/reports/generate (HTML)
	reqBody := map[string]any{
		"assessmentId":        asmtID,
		"targetHost":          "http://127.0.0.1:8080",
		"templateType":        "EXECUTIVE_SUMMARY",
		"format":              "HTML",
		"redactSensitiveData": true,
		"title":               "Test Executive Summary Report",
	}
	reqBytes, _ := json.Marshal(reqBody)

	genReq := httptest.NewRequest(http.MethodPost, "/api/v1/reports/generate", bytes.NewReader(reqBytes))
	genReq.Header.Set("Content-Type", "application/json")
	ctx, _ := tenant.WithID(genReq.Context(), tenantID)
	genReq = genReq.WithContext(ctx)

	genRec := httptest.NewRecorder()
	handler.ServeHTTP(genRec, genReq)

	if genRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for report generation, got %d: %s", genRec.Code, genRec.Body.String())
	}

	var genRes struct {
		Success bool                  `json:"success"`
		Data    httpapi.ReportItemDTO `json:"data"`
	}
	if err := json.Unmarshal(genRec.Body.Bytes(), &genRes); err != nil {
		t.Fatalf("failed to decode report generation response: %v", err)
	}
	if genRes.Data.ID == "" || genRes.Data.DownloadURL == "" {
		t.Fatalf("expected valid report ID and download URL, got %v", genRes.Data)
	}

	reportID := genRes.Data.ID

	// 2. GET /api/v1/reports
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports", nil)
	listReq = listReq.WithContext(ctx)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on report listing, got %d: %s", listRec.Code, listRec.Body.String())
	}

	var listRes struct {
		Success bool                    `json:"success"`
		Data    []httpapi.ReportItemDTO `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listRes); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listRes.Data) != 1 || listRes.Data[0].ID != reportID {
		t.Errorf("expected 1 report with ID %s, got %v", reportID, listRes.Data)
	}

	// 3. GET /api/v1/reports/{id}/download (HTML)
	dlReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports/"+reportID+"/download?format=HTML", nil)
	dlReq = dlReq.WithContext(ctx)
	dlRec := httptest.NewRecorder()
	handler.ServeHTTP(dlRec, dlReq)

	if dlRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on report download, got %d: %s", dlRec.Code, dlRec.Body.String())
	}
	if dlRec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected text/html Content-Type, got %s", dlRec.Header().Get("Content-Type"))
	}
	if !bytes.Contains(dlRec.Body.Bytes(), []byte("<!DOCTYPE html>")) {
		t.Errorf("expected valid HTML document output")
	}

	// 4. Generate PDF report
	pdfReqBody := map[string]any{
		"assessmentId":        asmtID,
		"targetHost":          "http://127.0.0.1:8080",
		"templateType":        "TECHNICAL_FINDINGS",
		"format":              "PDF",
		"redactSensitiveData": false,
	}
	pdfReqBytes, _ := json.Marshal(pdfReqBody)
	pdfGenReq := httptest.NewRequest(http.MethodPost, "/api/v1/reports/generate", bytes.NewReader(pdfReqBytes))
	pdfGenReq.Header.Set("Content-Type", "application/json")
	pdfGenReq = pdfGenReq.WithContext(ctx)

	pdfGenRec := httptest.NewRecorder()
	handler.ServeHTTP(pdfGenRec, pdfGenReq)

	if pdfGenRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for PDF generation, got %d: %s", pdfGenRec.Code, pdfGenRec.Body.String())
	}

	var pdfRes struct {
		Success bool                  `json:"success"`
		Data    httpapi.ReportItemDTO `json:"data"`
	}
	_ = json.Unmarshal(pdfGenRec.Body.Bytes(), &pdfRes)

	pdfDlReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports/"+pdfRes.Data.ID+"/download?format=PDF", nil)
	pdfDlReq = pdfDlReq.WithContext(ctx)
	pdfDlRec := httptest.NewRecorder()
	handler.ServeHTTP(pdfDlRec, pdfDlReq)

	if pdfDlRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for PDF download, got %d: %s", pdfDlRec.Code, pdfDlRec.Body.String())
	}
	if pdfDlRec.Header().Get("Content-Type") != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", pdfDlRec.Header().Get("Content-Type"))
	}
	if !bytes.HasPrefix(pdfDlRec.Body.Bytes(), []byte("%PDF-")) {
		t.Errorf("expected valid %%PDF- magic prefix")
	}
}

func TestHTTP_ReportsCrossTenantIsolation(t *testing.T) {
	srv, _ := setupReportTestServer(t)
	tenantA := uuid.New()
	tenantB := uuid.New()
	asmtID := uuid.New().String()
	handler := srv.Handler()

	// Tenant A generates report
	reqBody := map[string]any{
		"assessmentId": asmtID,
		"format":       "HTML",
	}
	reqBytes, _ := json.Marshal(reqBody)

	genReq := httptest.NewRequest(http.MethodPost, "/api/v1/reports/generate", bytes.NewReader(reqBytes))
	genReq.Header.Set("Content-Type", "application/json")
	ctxA, _ := tenant.WithID(genReq.Context(), tenantA)
	genReq = genReq.WithContext(ctxA)

	genRec := httptest.NewRecorder()
	handler.ServeHTTP(genRec, genReq)

	var genRes struct {
		Data httpapi.ReportItemDTO `json:"data"`
	}
	_ = json.Unmarshal(genRec.Body.Bytes(), &genRes)
	reportID := genRes.Data.ID

	// Tenant B lists reports -> expects empty list
	ctxB, _ := tenant.WithID(context.Background(), tenantB)
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports", nil)
	listReq = listReq.WithContext(ctxB)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	var listRes struct {
		Data []httpapi.ReportItemDTO `json:"data"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listRes)
	if len(listRes.Data) != 0 {
		t.Errorf("tenant B unexpectedly saw reports from Tenant A: %v", listRes.Data)
	}

	// Tenant B attempts download -> expects 404
	dlReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports/"+reportID+"/download", nil)
	dlReq = dlReq.WithContext(ctxB)
	dlRec := httptest.NewRecorder()
	handler.ServeHTTP(dlRec, dlReq)

	if dlRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant report download, got %d: %s", dlRec.Code, dlRec.Body.String())
	}
}
