package governance

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeExportMatrix(t *testing.T) {
	// 1. Developer cannot export Confidential (Findings) without explicit permission
	assert.False(t, AuthorizeExport("DEVELOPER", nil, ClassificationConfidential))

	// 2. Developer can export Internal (Remediations)
	assert.True(t, AuthorizeExport("DEVELOPER", nil, ClassificationInternal))

	// 3. Security Officer can export Confidential (Findings)
	assert.True(t, AuthorizeExport("SECURITY_OFFICER", nil, ClassificationConfidential))

	// 4. Security Officer cannot export Restricted (Audit Logs) unless Org Owner
	assert.False(t, AuthorizeExport("SECURITY_OFFICER", nil, ClassificationRestricted))

	// 5. Org Owner can export Restricted
	assert.True(t, AuthorizeExport("ORG_OWNER", nil, ClassificationRestricted))

	// 6. User with wildcard permission can export Restricted
	assert.True(t, AuthorizeExport("DEVELOPER", []string{"data:export:*"}, ClassificationRestricted))
}

func TestExportService_GenerateAndSanitizeJSON(t *testing.T) {
	svc := NewExportService()
	tenantID := uuid.New()

	records := []ExportRecord{
		{
			ID:        "find-001",
			Type:      "vulnerability",
			Title:     "SQL Injection with Bearer token-xyz12345678",
			Summary:   "Found vulnerable endpoint with password: secretPassword",
			Severity:  "HIGH",
			Metadata:  map[string]any{"key": "klv_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			CreatedAt: time.Now().UTC(),
		},
	}

	req := ExportRequest{
		TenantID:      tenantID,
		RequesterID:   "user-sec-1",
		RequesterRole: "SECURITY_OFFICER",
		Scope:         ScopeFindings,
		Format:        FormatJSON,
	}

	res, err := svc.GenerateExport(context.Background(), req, records)
	require.NoError(t, err)
	assert.Equal(t, ClassificationConfidential, res.Classification)
	assert.Equal(t, 1, res.RecordCount)
	assert.NotEmpty(t, res.ChecksumSHA256)
	assert.NotEmpty(t, res.DownloadToken)

	// Check sensitive content is sanitized in payload
	payloadStr := string(res.PayloadBytes)
	assert.NotContains(t, payloadStr, "token-xyz12345678")
	assert.NotContains(t, payloadStr, "secretPassword")
	assert.NotContains(t, payloadStr, "klv_live_0123456789abcdef")
	assert.Contains(t, payloadStr, "[REDACTED]")

	// Verify JSON structure
	var parsed []map[string]any
	err = json.Unmarshal(res.PayloadBytes, &parsed)
	require.NoError(t, err)
	assert.Len(t, parsed, 1)
}

func TestExportService_CSVFormat(t *testing.T) {
	svc := NewExportService()
	tenantID := uuid.New()

	records := []ExportRecord{
		{
			ID:        "rem-001",
			Type:      "remediation",
			Title:     "Patch OpenSSL",
			Summary:   "Upgrade openssl to v3.0.8",
			Severity:  "MEDIUM",
			CreatedAt: time.Now().UTC(),
		},
	}

	req := ExportRequest{
		TenantID:      tenantID,
		RequesterID:   "user-dev-1",
		RequesterRole: "DEVELOPER",
		Scope:         ScopeRemediations,
		Format:        FormatCSV,
	}

	res, err := svc.GenerateExport(context.Background(), req, records)
	require.NoError(t, err)
	assert.Equal(t, FormatCSV, res.Format)

	csvStr := string(res.PayloadBytes)
	assert.Contains(t, csvStr, "id,type,title,summary,severity,created_at")
	assert.Contains(t, csvStr, "rem-001,remediation,Patch OpenSSL,Upgrade openssl to v3.0.8,MEDIUM")
}

func TestExportService_DownloadTokenAndTenantIsolation(t *testing.T) {
	svc := NewExportService()
	tenantID := uuid.New()
	otherTenantID := uuid.New()

	req := ExportRequest{
		TenantID:      tenantID,
		RequesterID:   "user-owner",
		RequesterRole: "ORG_OWNER",
		Scope:         ScopeFindings,
		Format:        FormatJSON,
	}

	res, err := svc.GenerateExport(context.Background(), req, nil)
	require.NoError(t, err)

	// 1. Successful download by same tenant
	dl, err := svc.DownloadExport(tenantID, res.DownloadToken)
	require.NoError(t, err)
	assert.Equal(t, res.ExportID, dl.ExportID)

	// 2. Cross-tenant download blocked
	_, err = svc.DownloadExport(otherTenantID, res.DownloadToken)
	assert.ErrorIs(t, err, ErrTenantMismatch)

	// 3. Invalid token
	_, err = svc.DownloadExport(tenantID, "invalid-token-123")
	assert.ErrorIs(t, err, ErrInvalidDownloadToken)

	// 4. Expired token
	res.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
	_, err = svc.DownloadExport(tenantID, res.DownloadToken)
	assert.ErrorIs(t, err, ErrExportExpired)
}
