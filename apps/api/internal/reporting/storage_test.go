package reporting

import (
	"context"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureReportService(t *testing.T) {
	ctx := context.Background()
	artifactRepo := NewMemoryArtifactRepository()
	objectStore := NewMemoryObjectStore()
	snapshotRepo := NewMemorySnapshotRepository()
	signer := NewReportURLSigner([]byte("secret-signing-key-for-test-12345"))

	service := NewSecureReportService(artifactRepo, objectStore, snapshotRepo, signer)

	tenantID := uuid.New()
	reportID := uuid.New()
	assessmentID := uuid.New()

	htmlBytes := []byte("<!DOCTYPE html><html><body><h1>Audit Report</h1></body></html>")
	pdfBytes := []byte("%PDF-1.4\nstream\nTest PDF\nendstream\n%%EOF")

	t.Run("store report artifacts", func(t *testing.T) {
		recordHTML, err := service.StoreReportArtifact(ctx, tenantID, reportID, assessmentID, FormatHTML, htmlBytes, nil)
		require.NoError(t, err)
		assert.Equal(t, FormatHTML, recordHTML.Format)
		assert.Equal(t, int64(len(htmlBytes)), recordHTML.SizeBytes)
		assert.NotEmpty(t, recordHTML.SHA256Checksum)

		recordPDF, err := service.StoreReportArtifact(ctx, tenantID, reportID, assessmentID, FormatPDF, pdfBytes, nil)
		require.NoError(t, err)
		assert.Equal(t, FormatPDF, recordPDF.Format)
		assert.Equal(t, int64(len(pdfBytes)), recordPDF.SizeBytes)
	})

	t.Run("generate and download via ephemeral signed link", func(t *testing.T) {
		baseURL := "https://api.kelvin.internal/api/v1/reports/" + reportID.String() + "/download"
		downloadURL, err := service.GetReportDownloadURL(ctx, baseURL, tenantID, reportID, FormatHTML, 300*time.Second, "user-1")
		require.NoError(t, err)

		parsed, err := url.Parse(downloadURL)
		require.NoError(t, err)
		token := parsed.Query().Get("token")
		expiresStr := parsed.Query().Get("expires")
		expiresUnix, err := strconv.ParseInt(expiresStr, 10, 64)
		require.NoError(t, err)

		// Download content
		downloaded, artifact, err := service.DownloadReportContent(ctx, tenantID, reportID, FormatHTML, token, expiresUnix, "user-1")
		require.NoError(t, err)
		assert.Equal(t, htmlBytes, downloaded)
		assert.Equal(t, reportID, artifact.ReportID)
	})

	t.Run("reject tampered download token", func(t *testing.T) {
		expiresUnix := time.Now().UTC().Add(300 * time.Second).Unix()
		_, _, err := service.DownloadReportContent(ctx, tenantID, reportID, FormatHTML, "tampered-invalid-token", expiresUnix, "user-1")
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("reject expired token", func(t *testing.T) {
		pastUnix := time.Now().UTC().Add(-10 * time.Second).Unix()
		token := signer.GenerateToken(tenantID, reportID, FormatHTML, pastUnix)

		_, _, err := service.DownloadReportContent(ctx, tenantID, reportID, FormatHTML, token, pastUnix, "user-1")
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("revoke report artifacts", func(t *testing.T) {
		err := service.RevokeReport(ctx, tenantID, reportID, "Report released with premature finding data", "ciso-user")
		require.NoError(t, err)

		// Subsequent download URL generation rejected
		_, err = service.GetReportDownloadURL(ctx, "https://api.kelvin.internal", tenantID, reportID, FormatHTML, 300*time.Second, "user-1")
		assert.ErrorIs(t, err, ErrReportRevoked)

		// Direct download with valid token rejected
		futureUnix := time.Now().UTC().Add(300 * time.Second).Unix()
		token := signer.GenerateToken(tenantID, reportID, FormatHTML, futureUnix)
		_, _, err = service.DownloadReportContent(ctx, tenantID, reportID, FormatHTML, token, futureUnix, "user-1")
		assert.ErrorIs(t, err, ErrReportRevoked)
	})

	t.Run("artifact expiration enforcement", func(t *testing.T) {
		expiredReportID := uuid.New()
		pastTTL := -1 * time.Minute
		_, err := service.StoreReportArtifact(ctx, tenantID, expiredReportID, assessmentID, FormatHTML, htmlBytes, &pastTTL)
		require.NoError(t, err)

		_, err = service.GetReportDownloadURL(ctx, "https://api.kelvin.internal", tenantID, expiredReportID, FormatHTML, 300*time.Second, "user-1")
		assert.ErrorIs(t, err, ErrReportExpired)
	})

	t.Run("regenerate report artifact from snapshot", func(t *testing.T) {
		regenReportID := uuid.New()
		reportDoc := sampleValidReport()
		reportDoc.ReportID = regenReportID
		reportDoc.AssessmentID = assessmentID
		reportDoc.TenantID = tenantID

		snapshot := &ReportSnapshot{
			ID:              uuid.New(),
			TenantID:        tenantID,
			AssessmentID:    assessmentID,
			ReportID:        regenReportID,
			Title:           "Regenerated Report",
			SchemaVersion:   CurrentSchemaVersion,
			TemplateVersion: DefaultTemplateID,
			SnapshotData:    reportDoc,
			CreatedAt:       time.Now().UTC(),
		}
		require.NoError(t, snapshotRepo.SaveSnapshot(ctx, snapshot))

		renderer, err := NewReportRendererService(nil)
		require.NoError(t, err)

		record, err := service.RegenerateArtifact(ctx, tenantID, regenReportID, FormatHTML, renderer)
		require.NoError(t, err)
		assert.Equal(t, FormatHTML, record.Format)
		assert.Equal(t, regenReportID, record.ReportID)

		// Verify stored blob can be retrieved
		blob, err := objectStore.Get(ctx, record.StoragePath)
		require.NoError(t, err)
		assert.Contains(t, string(blob), reportDoc.Title)
	})
}
