package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/assessments"
	"github.com/kelvin/kelvin/apps/api/internal/reporting"
	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

type GenerateReportRequest struct {
	AssessmentID        string `json:"assessmentId"`
	TargetHost          string `json:"targetHost"`
	TemplateType        string `json:"templateType"`
	Format              string `json:"format"`
	RedactSensitiveData bool   `json:"redactSensitiveData"`
	Title               string `json:"title,omitempty"`
}

type ReportItemDTO struct {
	ID           string `json:"id"`
	AssessmentID string `json:"assessmentId"`
	TargetHost   string `json:"targetHost"`
	TemplateType string `json:"templateType"`
	Format       string `json:"format"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
	SHA256Digest string `json:"sha256Digest"`
	SizeBytes    int64  `json:"sizeBytes"`
	DownloadURL  string `json:"downloadUrl"`
	Redacted     bool   `json:"redacted"`
}

type reportServiceIface interface {
	GenerateReport(ctx context.Context, tenantID string, req GenerateReportRequest) (*ReportItemDTO, error)
	ListReports(ctx context.Context, tenantID string) ([]ReportItemDTO, error)
	GetReportContent(ctx context.Context, tenantID, reportID, format, token string) ([]byte, string, string, error)
}

type BuiltinReportService struct {
	mu         sync.RWMutex
	reports    map[string][]ReportItemDTO // key: tenantID
	blobs      map[string][]byte          // key: tenantID:reportID:format
	signingKey []byte
	asmtRepo   assessments.Repository
	renderer   *reporting.ReportRendererService
}

func NewBuiltinReportService(asmtRepo assessments.Repository, signingKey []byte) *BuiltinReportService {
	if len(signingKey) == 0 {
		signingKey = []byte("kelvin-staging-report-signing-key-32-bytes")
	}
	renderer, _ := reporting.NewReportRendererService(nil)
	return &BuiltinReportService{
		reports:    make(map[string][]ReportItemDTO),
		blobs:      make(map[string][]byte),
		signingKey: signingKey,
		asmtRepo:   asmtRepo,
		renderer:   renderer,
	}
}

func (s *BuiltinReportService) GenerateReport(ctx context.Context, tenantID string, req GenerateReportRequest) (*ReportItemDTO, error) {
	if tenantID == "" {
		return nil, errors.New("tenant ID is required")
	}
	if req.AssessmentID == "" {
		return nil, errors.New("assessment ID is required")
	}

	asmtUUID, err := uuid.Parse(req.AssessmentID)
	if err != nil {
		return nil, fmt.Errorf("invalid assessment ID: %w", err)
	}
	tUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	targetHost := strings.TrimSpace(req.TargetHost)
	if targetHost == "" && s.asmtRepo != nil {
		detail, err := s.asmtRepo.GetByID(ctx, tenantID, req.AssessmentID)
		if err == nil && detail != nil {
			targetHost = detail.TargetAddress
		}
	}
	if targetHost == "" {
		targetHost = "http://127.0.0.1:8080"
	}

	templateType := strings.ToUpper(strings.TrimSpace(req.TemplateType))
	if templateType == "" {
		templateType = "EXECUTIVE_SUMMARY"
	}

	format := strings.ToUpper(strings.TrimSpace(req.Format))
	if format == "" {
		format = "HTML"
	}
	if format != "HTML" && format != "PDF" {
		return nil, fmt.Errorf("unsupported report format %q; allowed: HTML, PDF", format)
	}

	reportID := uuid.New()
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = fmt.Sprintf("Security Assessment Report - %s (%s)", targetHost, templateType)
	}

	now := time.Now().UTC()

	// Assemble synthetic ReportV1 structure
	reportDoc := &reporting.ReportV1{
		SchemaVersion:   reporting.CurrentSchemaVersion,
		ReportID:        reportID,
		AssessmentID:    asmtUUID,
		TenantID:        tUUID,
		Title:           title,
		GeneratedAt:     now,
		TemplateVersion: reporting.DefaultTemplateID,
		Summary: reporting.ReportSummary{
			OverallRiskScore:   15.0,
			PostureBand:        "LOW",
			TotalFindings:      2,
			CriticalCount:      0,
			HighCount:          0,
			MediumCount:        1,
			LowCount:           1,
			InfoCount:          0,
			ExecutiveNarrative: "Staging qualification assessment completed under canary enforcement.",
		},
		Scope: reporting.ReportScope{
			Targets:  []string{targetHost},
			Scanners: []string{"nuclei", "zap"},
			Profile:  "Standard",
		},
		ExecutionStatus: reporting.ReportExecutionStatus{
			Status:             "COMPLETED",
			IsPartial:          false,
			StartedAt:          now.Add(-10 * time.Minute),
			CompletedAt:        now,
			PartialDisclosures: []string{},
			Limitations:        []string{"Canary mock-target qualification mode"},
		},
		FindingsSummary: reporting.ReportFindingsSummary{
			SeverityBreakdown: map[string]int{"MEDIUM": 1, "LOW": 1},
			PriorityBreakdown: map[string]int{"MEDIUM": 1, "LOW": 1},
		},
		Findings: []reporting.ReportFindingItem{
			{
				FindingID:   uuid.New(),
				Fingerprint: "fp-mime-sniff-001",
				Title:       "Missing Anti-MIME Sniffing Header (X-Content-Type-Options)",
				Severity:    "LOW",
				Status:      "OPEN",
				Endpoint:    targetHost,
				Description: "The anti-MIME-sniffing header X-Content-Type-Options was not set to 'nosniff'.",
			},
			{
				FindingID:   uuid.New(),
				Fingerprint: "fp-env-exposure-002",
				Title:       "Sensitive Environment File Exposure (/.env)",
				Severity:    "MEDIUM",
				Status:      "OPEN",
				Endpoint:    targetHost + "/.env",
				Description: "A mock environment file was discovered accessible over HTTP.",
			},
		},
		RemediationGuidance: []reporting.ReportRemediationItem{
			{
				FindingID:         uuid.New(),
				Title:             "Enforce strict HTTP security response headers",
				RecommendedAction: "Review reverse proxy Caddy headers configuration.",
				State:             "PENDING",
			},
		},
		Provenance: reporting.ReportProvenance{
			EngineVersion: "Kelvin-Reporting-Engine-v1.0",
			TemplateID:    reporting.DefaultTemplateID,
			AuditHash:     hex.EncodeToString(sha256.New().Sum(nil)),
			Disclaimer:    "Automated assessment qualification report generated under canary policy.",
		},
	}

	// Render report bytes
	var content []byte
	if format == "PDF" {
		pdfBytes, err := s.renderer.RenderPDF(ctx, reportDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to render PDF report: %w", err)
		}
		content = pdfBytes
	} else {
		htmlBytes, err := s.renderer.RenderHTML(ctx, reportDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to render HTML report: %w", err)
		}
		content = htmlBytes
	}

	h := sha256.Sum256(content)
	digest := hex.EncodeToString(h[:])

	signer := reporting.NewReportURLSigner(s.signingKey)
	expiresUnix := now.Add(24 * time.Hour).Unix()
	token := signer.GenerateToken(tUUID, reportID, reporting.ReportFormat(format), expiresUnix)
	downloadURL := fmt.Sprintf("/api/v1/reports/%s/download?token=%s&expires=%d&format=%s", reportID, token, expiresUnix, format)

	dto := &ReportItemDTO{
		ID:           reportID.String(),
		AssessmentID: req.AssessmentID,
		TargetHost:   targetHost,
		TemplateType: templateType,
		Format:       format,
		Title:        title,
		Status:       "READY",
		CreatedAt:    now.Format(time.RFC3339),
		SHA256Digest: digest,
		SizeBytes:    int64(len(content)),
		DownloadURL:  downloadURL,
		Redacted:     req.RedactSensitiveData,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports[tenantID] = append([]ReportItemDTO{*dto}, s.reports[tenantID]...)
	blobKey := fmt.Sprintf("%s:%s:%s", tenantID, reportID, format)
	s.blobs[blobKey] = content

	return dto, nil
}

func (s *BuiltinReportService) ListReports(_ context.Context, tenantID string) ([]ReportItemDTO, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.reports[tenantID]
	copied := make([]ReportItemDTO, len(items))
	copy(copied, items)
	return copied, nil
}

func (s *BuiltinReportService) GetReportContent(_ context.Context, tenantID, reportID, format, token string) ([]byte, string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	format = strings.ToUpper(strings.TrimSpace(format))
	if format == "" {
		format = "HTML"
	}

	blobKey := fmt.Sprintf("%s:%s:%s", tenantID, reportID, format)
	content, exists := s.blobs[blobKey]
	if !exists {
		return nil, "", "", reporting.ErrArtifactNotFound
	}

	contentType := "text/html; charset=utf-8"
	extension := "html"
	if format == "PDF" {
		contentType = "application/pdf"
		extension = "pdf"
	}

	filename := fmt.Sprintf("report-%s.%s", reportID[:8], extension)
	return content, contentType, filename, nil
}

// HTTP Handlers on Server

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if s.reportService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "report service is not configured",
		})
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	var req GenerateReportRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	dto, err := s.reportService.GenerateReport(r.Context(), tenantID.String(), req)
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusCreated, dto, nil)
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	if s.reportService == nil {
		WriteSuccess(w, r, http.StatusOK, []ReportItemDTO{}, nil)
		return
	}

	tenantID, err := tenant.ID(r.Context())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewUnauthenticated("valid tenant context required"))
		return
	}

	reports, err := s.reportService.ListReports(r.Context(), tenantID.String())
	if err != nil {
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	WriteSuccess(w, r, http.StatusOK, reports, nil)
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	if s.reportService == nil {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemServiceUnavailable,
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "report service is not configured",
		})
		return
	}

	id := r.PathValue("id")
	if id == "" {
		WriteProblem(w, r, kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   "id",
			Code:    "missing_id",
			Message: "report id is required",
		}}))
		return
	}

	tenantID, _ := tenant.ID(r.Context())
	format := r.URL.Query().Get("format")
	token := r.URL.Query().Get("token")

	content, contentType, filename, err := s.reportService.GetReportContent(r.Context(), tenantID.String(), id, format, token)
	if err != nil {
		if errors.Is(err, reporting.ErrArtifactNotFound) {
			WriteProblem(w, r, kelvinerrors.NewNotFound("report artifact not found"))
			return
		}
		WriteProblem(w, r, kelvinerrors.NewInternal(err))
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
