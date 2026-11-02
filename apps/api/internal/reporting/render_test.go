package reporting

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportRendererService(t *testing.T) {
	service, err := NewReportRendererService(nil)
	require.NoError(t, err)

	report := sampleValidReport()

	t.Run("render valid HTML report", func(t *testing.T) {
		ctx := context.Background()
		htmlBytes, err := service.RenderHTML(ctx, report)
		require.NoError(t, err)

		htmlStr := string(htmlBytes)
		assert.Contains(t, htmlStr, "<!DOCTYPE html>")
		assert.Contains(t, htmlStr, report.Title)
		assert.Contains(t, htmlStr, "Executive Summary &amp; Posture Score")
		assert.Contains(t, htmlStr, "Remote Code Execution via Spring4Shell")
		assert.Contains(t, htmlStr, "[REDACTED_AUTHORIZATION_TOKEN]")
		assert.Contains(t, htmlStr, "Upgrade Spring Framework")
		assert.Contains(t, htmlStr, report.Provenance.AuditHash)
	})

	t.Run("anti-XSS escaping test", func(t *testing.T) {
		ctx := context.Background()
		xssReport := sampleValidReport()
		xssReport.Title = "<script>alert('xss-title')</script>"
		xssReport.Findings[0].Title = "<img src=x onerror=alert('xss-finding')>"
		xssReport.Findings[0].Endpoint = "https://example.com/<svg onload=alert(1)>"

		htmlBytes, err := service.RenderHTML(ctx, xssReport)
		require.NoError(t, err)

		htmlStr := string(htmlBytes)
		// Must NOT contain raw unescaped script or event tags
		assert.NotContains(t, htmlStr, "<script>alert('xss-title')</script>")
		assert.NotContains(t, htmlStr, "<img src=x onerror=alert('xss-finding')>")
		assert.NotContains(t, htmlStr, "<svg onload=alert(1)>")

		// Must contain escaped HTML entities
		assert.Contains(t, htmlStr, "&lt;script&gt;alert(&#39;xss-title&#39;)&lt;/script&gt;")
		assert.Contains(t, htmlStr, "&lt;img src=x onerror=alert(&#39;xss-finding&#39;)&gt;")
	})

	t.Run("render valid PDF report", func(t *testing.T) {
		ctx := context.Background()
		pdfBytes, err := service.RenderPDF(ctx, report)
		require.NoError(t, err)
		assert.NotEmpty(t, pdfBytes)

		// Verify PDF magic bytes and trailer
		assert.True(t, strings.HasPrefix(string(pdfBytes), "%PDF-1.4"))
		assert.True(t, strings.HasSuffix(strings.TrimSpace(string(pdfBytes)), "%%EOF"))
	})

	t.Run("partial assessment notice rendering", func(t *testing.T) {
		ctx := context.Background()
		partialReport := sampleValidReport()
		partialReport.ExecutionStatus.IsPartial = true
		partialReport.ExecutionStatus.PartialDisclosures = []string{"Scanner process aborted after 10m timeout"}

		htmlBytes, err := service.RenderHTML(ctx, partialReport)
		require.NoError(t, err)

		htmlStr := string(htmlBytes)
		assert.Contains(t, htmlStr, "Partial Assessment Notice:")
		assert.Contains(t, htmlStr, "Scanner process aborted after 10m timeout")
	})

	t.Run("nil report error", func(t *testing.T) {
		ctx := context.Background()
		_, err := service.RenderHTML(ctx, nil)
		assert.ErrorIs(t, err, ErrNilReportDocument)
	})

	t.Run("context cancellation handling", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // canceled immediately

		_, err := service.RenderHTML(ctx, report)
		assert.Error(t, err)
	})

	t.Run("exceeding maximum findings limit", func(t *testing.T) {
		ctx := context.Background()
		largeReport := sampleValidReport()
		largeReport.Findings = make([]ReportFindingItem, MaxFindingsPerReport+1)
		for i := range largeReport.Findings {
			largeReport.Findings[i] = ReportFindingItem{
				FindingID: uuid.New(),
				Title:     "Bulk Finding",
				Severity:  "LOW",
				Status:    "OPEN",
				Endpoint:  "https://example.com",
			}
		}

		_, err := service.RenderHTML(ctx, largeReport)
		assert.ErrorIs(t, err, ErrRenderingLimit)
	})
}
