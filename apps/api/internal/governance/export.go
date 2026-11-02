package governance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/integrations"
	"github.com/kelvin/kelvin/apps/api/internal/redaction"
)

var (
	ErrUnauthorizedExport     = errors.New("governance: caller not authorized to export requested classification")
	ErrTenantMismatch         = errors.New("governance: tenant boundary violation during export")
	ErrUnsupportedScope       = errors.New("governance: unsupported data export scope")
	ErrUnsupportedFormat      = errors.New("governance: unsupported data export format")
	ErrExportExpired          = errors.New("governance: download token has expired")
	ErrInvalidDownloadToken   = errors.New("governance: invalid or unrecognized download token")
)

const (
	ClassificationPublic       = "PUBLIC"
	ClassificationInternal     = "INTERNAL"
	ClassificationConfidential = "CONFIDENTIAL"
	ClassificationRestricted   = "RESTRICTED"

	ScopeFindings     = "FINDINGS"
	ScopeReports      = "REPORTS"
	ScopeAuditLogs    = "AUDIT_LOGS"
	ScopeRemediations = "REMEDIATIONS"

	FormatJSON = "JSON"
	FormatCSV  = "CSV"

	ExportTokenTTL = 15 * time.Minute
)

// ScopeClassification maps each domain scope to its required governance classification.
var ScopeClassification = map[string]string{
	ScopeFindings:     ClassificationConfidential,
	ScopeReports:      ClassificationConfidential,
	ScopeRemediations: ClassificationInternal,
	ScopeAuditLogs:    ClassificationRestricted,
}

// ExportRequest specifies parameters for an enterprise data extraction request.
type ExportRequest struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	RequesterID   string    `json:"requester_id"`
	RequesterRole string    `json:"requester_role"`
	Permissions   []string  `json:"permissions"`
	Scope         string    `json:"scope"`  // FINDINGS, REPORTS, AUDIT_LOGS, REMEDIATIONS
	Format        string    `json:"format"` // JSON, CSV
}

// ExportRecord represents a generalized data item to be exported.
type ExportRecord struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Summary   string         `json:"summary"`
	Severity  string         `json:"severity,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// ExportResult contains the metadata, payload, and temporary download credentials.
type ExportResult struct {
	ExportID       uuid.UUID `json:"export_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	RequesterID    string    `json:"requester_id"`
	Classification string    `json:"classification"`
	Scope          string    `json:"scope"`
	Format         string    `json:"format"`
	RecordCount    int       `json:"record_count"`
	PayloadBytes   []byte    `json:"-"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	DownloadToken  string    `json:"download_token"`
	DownloadURL    string    `json:"download_url"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// ExportService coordinates RBAC verification, sanitization, serialization, and ephemeral delivery.
type ExportService struct {
	mu       sync.RWMutex
	exports  map[string]*ExportResult // key: downloadToken
	redactor *redaction.Redactor
}

func NewExportService() *ExportService {
	return &ExportService{
		exports:  make(map[string]*ExportResult),
		redactor: redaction.NewDefaultRedactor(),
	}
}

// AuthorizeExport verifies that the requester has sufficient clearance for the target classification.
func AuthorizeExport(role string, permissions []string, classification string) bool {
	// Super permissions
	for _, p := range permissions {
		if p == "*" || p == "data:export:*" {
			return true
		}
	}

	normalizedRole := strings.ToUpper(strings.TrimSpace(role))

	switch classification {
	case ClassificationPublic, ClassificationInternal:
		for _, p := range permissions {
			if p == "data:export" || p == "data:export:internal" {
				return true
			}
		}
		return normalizedRole == "ORG_OWNER" || normalizedRole == "SECURITY_OFFICER" ||
			normalizedRole == "COMPLIANCE_AUDITOR" || normalizedRole == "DEVELOPER"

	case ClassificationConfidential:
		for _, p := range permissions {
			if p == "data:export" || p == "data:export:confidential" {
				return true
			}
		}
		return normalizedRole == "ORG_OWNER" || normalizedRole == "SECURITY_OFFICER" ||
			normalizedRole == "COMPLIANCE_AUDITOR"

	case ClassificationRestricted:
		for _, p := range permissions {
			if p == "data:export:restricted" {
				return true
			}
		}
		// Only Org Owner can export Restricted data (e.g. Audit Logs) by default
		return normalizedRole == "ORG_OWNER"

	default:
		return false
	}
}

// SanitizeRecord ensures secrets, bearer tokens, and credentials in records are redacted.
func (s *ExportService) SanitizeRecord(rec ExportRecord) ExportRecord {
	rec.Title = integrations.RedactSensitiveContent(s.redactor.RedactString(rec.Title))
	rec.Summary = integrations.RedactSensitiveContent(s.redactor.RedactString(rec.Summary))
	if len(rec.Metadata) > 0 {
		metaBytes, err := json.Marshal(rec.Metadata)
		if err == nil {
			redactedMeta := integrations.RedactSensitiveContent(s.redactor.RedactString(string(metaBytes)))
			var cleanedMap map[string]any
			if err := json.Unmarshal([]byte(redactedMeta), &cleanedMap); err == nil {
				rec.Metadata = cleanedMap
			}
		}
	}
	return rec
}

// GenerateExport processes and formats data records into a secure, checksummed export bundle.
func (s *ExportService) GenerateExport(
	ctx context.Context,
	req ExportRequest,
	records []ExportRecord,
) (*ExportResult, error) {
	if req.TenantID == uuid.Nil {
		return nil, ErrTenantMismatch
	}

	classification, ok := ScopeClassification[strings.ToUpper(req.Scope)]
	if !ok {
		return nil, ErrUnsupportedScope
	}

	if !AuthorizeExport(req.RequesterRole, req.Permissions, classification) {
		return nil, ErrUnauthorizedExport
	}

	reqFormat := strings.ToUpper(strings.TrimSpace(req.Format))
	if reqFormat != FormatJSON && reqFormat != FormatCSV {
		return nil, ErrUnsupportedFormat
	}

	// Sanitize records
	sanitized := make([]ExportRecord, len(records))
	for i, r := range records {
		sanitized[i] = s.SanitizeRecord(r)
	}

	var payload []byte
	var err error

	if reqFormat == FormatJSON {
		payload, err = json.MarshalIndent(sanitized, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("governance: failed to marshal export json: %w", err)
		}
	} else {
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)
		_ = writer.Write([]string{"id", "type", "title", "summary", "severity", "created_at"})
		for _, r := range sanitized {
			_ = writer.Write([]string{
				r.ID,
				r.Type,
				r.Title,
				r.Summary,
				r.Severity,
				r.CreatedAt.UTC().Format(time.RFC3339),
			})
		}
		writer.Flush()
		payload = buf.Bytes()
	}

	// Compute SHA-256 Checksum
	h := sha256.Sum256(payload)
	checksum := hex.EncodeToString(h[:])

	// Generate Cryptographic 256-bit Download Token
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	downloadToken := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	expiresAt := now.Add(ExportTokenTTL)

	result := &ExportResult{
		ExportID:       uuid.New(),
		TenantID:       req.TenantID,
		RequesterID:    req.RequesterID,
		Classification: classification,
		Scope:          req.Scope,
		Format:         reqFormat,
		RecordCount:    len(sanitized),
		PayloadBytes:   payload,
		ChecksumSHA256: checksum,
		DownloadToken:  downloadToken,
		DownloadURL:    fmt.Sprintf("/api/v1/data-exports/%s/download?token=%s", req.TenantID, downloadToken),
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
	}

	s.mu.Lock()
	s.exports[downloadToken] = result
	s.mu.Unlock()

	return result, nil
}

// DownloadExport validates the download token, enforces tenant boundary, and verifies expiration.
func (s *ExportService) DownloadExport(tenantID uuid.UUID, token string) (*ExportResult, error) {
	s.mu.RLock()
	res, ok := s.exports[token]
	s.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidDownloadToken
	}

	if res.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}

	if time.Now().UTC().After(res.ExpiresAt) {
		return nil, ErrExportExpired
	}

	return res, nil
}
