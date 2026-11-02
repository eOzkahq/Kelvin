package evidence_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

func TestEvidenceItem_Validation(t *testing.T) {
	tenantID := uuid.New().String()
	projectID := uuid.New().String()
	assessmentID := uuid.New().String()
	jobID := uuid.New().String()

	content := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World")
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])

	validItem := func() *evidence.EvidenceItem {
		return &evidence.EvidenceItem{
			ID:               uuid.New().String(),
			TenantID:         tenantID,
			ProjectID:        projectID,
			AssessmentID:     assessmentID,
			JobID:            jobID,
			EvidenceType:     evidence.TypeHTTPObservation,
			Provenance:       evidence.ProvenanceRawScanner,
			ContentType:      "text/plain",
			InlineContent:    string(content),
			ChecksumSHA256:   checksum,
			SizeBytes:        int64(len(content)),
			RedactionStatus:  evidence.RedactionUnredactedInternal,
			SensitivityLevel: evidence.SensitivityInternal,
			Status:           evidence.StatusActive,
			RetentionDays:    90,
			ExpiresAt:        time.Now().UTC().AddDate(0, 0, 90),
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}
	}

	t.Run("valid item passes", func(t *testing.T) {
		item := validItem()
		require.NoError(t, item.Validate())
	})

	t.Run("invalid tenant_id fails", func(t *testing.T) {
		item := validItem()
		item.TenantID = "not-a-uuid"
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "invalid tenant_id")
	})

	t.Run("invalid evidence_type fails", func(t *testing.T) {
		item := validItem()
		item.EvidenceType = "UNKNOWN_TYPE"
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "invalid evidence_type")
	})

	t.Run("invalid provenance fails", func(t *testing.T) {
		item := validItem()
		item.Provenance = "INVALID_PROVENANCE"
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "invalid provenance")
	})

	t.Run("invalid sensitivity_level fails", func(t *testing.T) {
		item := validItem()
		item.SensitivityLevel = "TOP_SECRET"
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "invalid sensitivity_level")
	})

	t.Run("disallowed executable mime type fails", func(t *testing.T) {
		item := validItem()
		item.ContentType = "application/x-msdownload"
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "disallowed or executable content_type")
	})

	t.Run("invalid checksum length fails", func(t *testing.T) {
		item := validItem()
		item.ChecksumSHA256 = "1234abcd"
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "checksum_sha256 must be a 64-character")
	})

	t.Run("missing both inline and storage ref fails", func(t *testing.T) {
		item := validItem()
		item.InlineContent = ""
		item.StorageRef = ""
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "either inline_content or storage_ref must be provided")
	})

	t.Run("inline content exceeds limit fails", func(t *testing.T) {
		item := validItem()
		item.InlineContent = strings.Repeat("a", evidence.MaxInlineSizeBytes+1)
		require.Error(t, item.Validate())
		assert.Contains(t, item.Validate().Error(), "exceeds maximum threshold")
	})
}

func TestNewEvidenceItem(t *testing.T) {
	tenantID := uuid.New().String()
	projectID := uuid.New().String()
	assessmentID := uuid.New().String()
	jobID := uuid.New().String()

	content := []byte("X-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff")

	item, err := evidence.NewEvidenceItem(
		tenantID,
		projectID,
		assessmentID,
		jobID,
		evidence.TypeSecurityHeaderDiff,
		evidence.ProvenanceCuratedFinding,
		"text/plain",
		content,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, item.ID)
	assert.Equal(t, tenantID, item.TenantID)
	assert.Equal(t, projectID, item.ProjectID)
	assert.Equal(t, assessmentID, item.AssessmentID)
	assert.Equal(t, jobID, item.JobID)
	assert.Equal(t, evidence.TypeSecurityHeaderDiff, item.EvidenceType)
	assert.Equal(t, evidence.ProvenanceCuratedFinding, item.Provenance)
	assert.Equal(t, string(content), item.InlineContent)
	assert.Equal(t, int64(len(content)), item.SizeBytes)
	assert.Equal(t, evidence.SensitivityInternal, item.SensitivityLevel)
	assert.Equal(t, evidence.RedactionUnredactedInternal, item.RedactionStatus)
	assert.Equal(t, evidence.StatusActive, item.Status)
	assert.Equal(t, 90, item.RetentionDays)
}

func TestSanitizeHeaders(t *testing.T) {
	rawHeaders := map[string][]string{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer secret_jwt_token_12345"},
		"Cookie":        {"session=abcde12345; auth=true"},
		"X-Api-Key":     {"secret-key-123"},
		"User-Agent":    {"Kelvin-Scanner/1.0"},
	}

	sanitized, redactedKeys := evidence.SanitizeHeaders(rawHeaders)

	assert.Equal(t, []string{"application/json"}, sanitized["Content-Type"])
	assert.Equal(t, []string{"Kelvin-Scanner/1.0"}, sanitized["User-Agent"])

	assert.Contains(t, sanitized["Authorization"][0], "[REDACTED]")
	assert.Contains(t, sanitized["Cookie"][0], "[REDACTED]")
	assert.Contains(t, sanitized["X-Api-Key"][0], "[REDACTED]")

	assert.ElementsMatch(t, []string{"Authorization", "Cookie", "X-Api-Key"}, redactedKeys)
}

func TestIsSafeMimeType(t *testing.T) {
	safeTypes := []string{
		"text/plain",
		"text/html; charset=utf-8",
		"application/json",
		"image/png",
		"application/pdf",
	}
	for _, st := range safeTypes {
		assert.True(t, evidence.IsSafeMimeType(st), "expected %s to be safe", st)
	}

	unsafeTypes := []string{
		"application/x-msdownload",
		"application/x-executable",
		"application/x-sh",
		"application/x-bat",
		"application/vnd.microsoft.portable-executable",
		"",
	}
	for _, ut := range unsafeTypes {
		assert.False(t, evidence.IsSafeMimeType(ut), "expected %s to be disallowed", ut)
	}
}
