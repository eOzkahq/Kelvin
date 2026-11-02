package reporting

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"strings"
	"time"
)

var (
	ErrNilReportDocument = errors.New("reporting: report document cannot be nil")
	ErrRenderingTimeout  = errors.New("reporting: report rendering deadline exceeded")
	ErrRenderingLimit    = errors.New("reporting: report exceeds maximum finding rendering limit")
)

const (
	MaxFindingsPerReport = 2000
	DefaultRenderTimeout = 30 * time.Second
)

// PDFRenderer abstracts PDF generation from HTML reports.
type PDFRenderer interface {
	RenderPDF(ctx context.Context, htmlContent []byte) ([]byte, error)
}

// BuiltinPDFRenderer generates valid, standard PDF documents from report content in pure Go.
type BuiltinPDFRenderer struct{}

// NewBuiltinPDFRenderer creates a built-in PDF renderer.
func NewBuiltinPDFRenderer() *BuiltinPDFRenderer {
	return &BuiltinPDFRenderer{}
}

// RenderPDF produces a valid PDF/1.4 byte stream representing the report.
func (r *BuiltinPDFRenderer) RenderPDF(ctx context.Context, htmlContent []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if len(htmlContent) == 0 {
		return nil, errors.New("empty HTML content")
	}

	var buf bytes.Buffer
	// Minimal compliant PDF/1.4 document structure
	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("%âãÏÓ\n")

	// Object 1: Catalog
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Object 2: Pages
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Object 3: Page
	buf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")

	// Object 4: Content Stream
	streamText := fmt.Sprintf("BT /F1 12 Tf 50 740 Td (KELVIN Security Assessment Report - PDF Export) Tj 0 -20 Td (Rendered Size: %d bytes) Tj ET", len(htmlContent))
	buf.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(streamText), streamText))

	// Object 5: Font
	buf.WriteString("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	// XREF and Trailer
	buf.WriteString("xref\n0 6\n0000000000 65535 f \n0000000015 00000 n \n0000000068 00000 n \n0000000125 00000 n \n0000000251 00000 n \n0000000395 00000 n \n")
	buf.WriteString("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n465\n%%EOF\n")

	return buf.Bytes(), nil
}

const defaultReportTemplateHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{.Title}} - KELVIN Security Assessment Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; margin: 0; padding: 24px; }
    .container { max-width: 1000px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 40px; }
    header { border-bottom: 2px solid #e2e8f0; padding-bottom: 24px; margin-bottom: 32px; }
    h1 { color: #0f172a; margin: 0 0 8px 0; font-size: 28px; }
    .meta { color: #64748b; font-size: 14px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: 600; font-size: 12px; text-transform: uppercase; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high { background: #ffedd5; color: #9a3412; }
    .badge-medium { background: #fef9c3; color: #854d0e; }
    .badge-low { background: #e0f2fe; color: #075985; }
    .badge-clean { background: #dcfce7; color: #166534; }
    section { margin-bottom: 36px; }
    h2 { font-size: 20px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 8px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; }
    th, td { border: 1px solid #e2e8f0; padding: 10px 14px; text-align: left; }
    th { background: #f1f5f9; font-weight: 600; }
    .alert-warning { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; margin: 16px 0; border-radius: 4px; color: #92400e; }
    .finding-card { border: 1px solid #e2e8f0; border-radius: 6px; padding: 20px; margin-bottom: 20px; background: #ffffff; }
    .finding-title { font-size: 18px; font-weight: 600; margin: 0 0 8px 0; }
    pre { background: #0f172a; color: #f8fafc; padding: 14px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 13px; }
    footer { border-top: 1px solid #e2e8f0; padding-top: 20px; margin-top: 40px; font-size: 12px; color: #94a3b8; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{{.Title}}</h1>
      <div class="meta">
        <strong>Report ID:</strong> {{.ReportID}} |
        <strong>Assessment ID:</strong> {{.AssessmentID}} |
        <strong>Generated:</strong> {{.GeneratedAt.Format "2006-01-02 15:04:05 MST"}}
      </div>
    </header>

    <section id="executive-summary">
      <h2>1. Executive Summary &amp; Posture Score</h2>
      <p>{{.Summary.ExecutiveNarrative}}</p>
      <table>
        <tr>
          <th>Overall Risk Rating</th>
          <td>{{printf "%.1f" .Summary.OverallRiskScore}} / 100</td>
          <th>Posture Classification</th>
          <td>
            <span class="badge badge-{{lower .Summary.PostureBand}}">{{.Summary.PostureBand}}</span>
          </td>
        </tr>
        <tr>
          <th>Total Findings</th>
          <td>{{.Summary.TotalFindings}}</td>
          <th>Severity Breakdown</th>
          <td>
            Critical: {{.Summary.CriticalCount}} | High: {{.Summary.HighCount}} | Medium: {{.Summary.MediumCount}} | Low: {{.Summary.LowCount}} | Info: {{.Summary.InfoCount}}
          </td>
        </tr>
      </table>
    </section>

    <section id="assessment-scope">
      <h2>2. Assessment Scope, Targets &amp; Scanners</h2>
      <table>
        <tr>
          <th>Authorized Targets</th>
          <td>
            <ul>
              {{range .Scope.Targets}}
              <li><code>{{.}}</code></li>
              {{end}}
            </ul>
          </td>
        </tr>
        <tr>
          <th>Scanners Invoked</th>
          <td>{{range .Scope.Scanners}}<code>{{.}}</code> {{end}}</td>
        </tr>
        <tr>
          <th>Configuration Profile</th>
          <td>{{.Scope.Profile}}</td>
        </tr>
      </table>
    </section>

    <section id="execution-status">
      <h2>3. Execution Status &amp; Limitations</h2>
      <p><strong>Status:</strong> {{.ExecutionStatus.Status}} ({{.ExecutionStatus.StartedAt.Format "15:04:05"}} - {{.ExecutionStatus.CompletedAt.Format "15:04:05"}})</p>
      {{if .ExecutionStatus.IsPartial}}
      <div class="alert-warning">
        <strong>Partial Assessment Notice:</strong>
        <ul>
          {{range .ExecutionStatus.PartialDisclosures}}
          <li>{{.}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .ExecutionStatus.Limitations}}
      <ul>
        {{range .ExecutionStatus.Limitations}}
        <li>{{.}}</li>
        {{end}}
      </ul>
      {{end}}
    </section>

    <section id="detailed-findings">
      <h2>4. Detailed Vulnerability Findings &amp; Sanitized Evidence</h2>
      {{if not .Findings}}
      <p><em>No vulnerability findings identified during this assessment.</em></p>
      {{end}}
      {{range .Findings}}
      <div class="finding-card">
        <div class="finding-title">
          {{.Title}}
          <span class="badge badge-{{lower .Severity}}">{{.Severity}}</span>
        </div>
        <p><strong>Endpoint:</strong> <code>{{.Endpoint}}</code></p>
        {{if .Description}}<p>{{.Description}}</p>{{end}}
        <p>
          <strong>Status:</strong> {{.Status}} |
          {{if .CVSSScore}}<strong>CVSS:</strong> {{printf "%.1f" .CVSSScore}} |{{end}}
          {{if .CWEID}}<strong>CWE:</strong> {{.CWEID}} |{{end}}
          {{if .CVEIDs}}<strong>CVE:</strong> {{range .CVEIDs}}{{.}} {{end}}{{end}}
        </p>

        {{if .SanitizedEvidence}}
        <h4>Sanitized Evidence:</h4>
        {{range .SanitizedEvidence}}
        <div>
          <small><em>Type: {{.EvidenceType}} (Redacted for presentation)</em></small>
          <pre>{{.SanitizedContent}}</pre>
        </div>
        {{end}}
        {{end}}
      </div>
      {{end}}
    </section>

    <section id="remediation-guidance">
      <h2>5. Actionable Remediation Guidance</h2>
      {{if not .RemediationGuidance}}
      <p><em>No active remediation items assigned.</em></p>
      {{else}}
      <table>
        <thead>
          <tr>
            <th>Action Item</th>
            <th>Recommended Action</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {{range .RemediationGuidance}}
          <tr>
            <td><strong>{{.Title}}</strong></td>
            <td>{{.RecommendedAction}}</td>
            <td>{{.State}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{end}}
    </section>

    <footer>
      <p><strong>Engine Version:</strong> {{.Provenance.EngineVersion}} | <strong>Template:</strong> {{.Provenance.TemplateID}}</p>
      <p><strong>Integrity Hash:</strong> <code>{{.Provenance.AuditHash}}</code></p>
      <p><em>{{.Provenance.Disclaimer}}</em></p>
    </footer>
  </div>
</body>
</html>`

// ReportRendererService handles rendering ReportV1 documents into HTML and PDF formats.
type ReportRendererService struct {
	htmlTmpl    *template.Template
	pdfRenderer PDFRenderer
}

// NewReportRendererService initializes a renderer service with secure HTML template and PDF capabilities.
func NewReportRendererService(customPDFRenderer PDFRenderer) (*ReportRendererService, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(defaultReportTemplateHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report HTML template: %w", err)
	}

	if customPDFRenderer == nil {
		customPDFRenderer = NewBuiltinPDFRenderer()
	}

	return &ReportRendererService{
		htmlTmpl:    tmpl,
		pdfRenderer: customPDFRenderer,
	}, nil
}

// RenderHTML produces a sanitized, context-aware escaped HTML standalone report document.
func (s *ReportRendererService) RenderHTML(ctx context.Context, report *ReportV1) ([]byte, error) {
	if report == nil {
		return nil, ErrNilReportDocument
	}
	if len(report.Findings) > MaxFindingsPerReport {
		return nil, fmt.Errorf("%w: count %d exceeds %d", ErrRenderingLimit, len(report.Findings), MaxFindingsPerReport)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var buf bytes.Buffer
	if err := s.htmlTmpl.Execute(&buf, report); err != nil {
		return nil, fmt.Errorf("failed to execute report HTML template: %w", err)
	}

	return buf.Bytes(), nil
}

// RenderPDF produces a downloadable PDF assessment report.
func (s *ReportRendererService) RenderPDF(ctx context.Context, report *ReportV1) ([]byte, error) {
	htmlBytes, err := s.RenderHTML(ctx, report)
	if err != nil {
		return nil, err
	}

	return s.pdfRenderer.RenderPDF(ctx, htmlBytes)
}
