package adapters

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxNucleiReportBytes = 4 << 20
const maxNucleiFindings = 10000

var nucleiURLQuery = regexp.MustCompile(`(?i)(https?://[^?\s<>]+)\?[^\s<>]+`)

type nucleiJSONLEntry struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Author         any      `json:"author"`
		Tags           []string `json:"tags"`
		Description    string   `json:"description"`
		Reference      any      `json:"reference"`
		Severity       string   `json:"severity"`
		Classification struct {
			CVSSScore float64  `json:"cvss-score"`
			CVEID     []string `json:"cve-id"`
			CWEID     []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	IP               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
	CurlCommand      string   `json:"curl-command"`
	MatcherName      string   `json:"matcher-name"`
}

// NormalizeNucleiReport converts bounded Nuclei JSONL output into
// Kelvin's output envelope. Target identity comes from the validated task,
// never from scanner-controlled report fields. Raw request/response and URLs
// are sanitized and strictly bound.
func NormalizeNucleiReport(task Task, raw []byte, scannerVersion, templateCatalogVersion, templateCatalogDigest string, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerNuclei || scannerVersion == "" || templateCatalogVersion != "kelvin.safe.web.v1" || templateCatalogDigest == "" {
		return Result{}, fmt.Errorf("adapters: invalid Nuclei report context")
	}
	if !started.IsZero() && completed.Before(started) {
		return Result{}, fmt.Errorf("adapters: invalid Nuclei timing context")
	}
	if len(raw) > maxNucleiReportBytes {
		return Result{}, fmt.Errorf("adapters: Nuclei report exceeds %d bytes", maxNucleiReportBytes)
	}

	target, err := url.Parse(task.Target)
	if err != nil || target.Hostname() == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return Result{}, fmt.Errorf("adapters: Nuclei task target is invalid")
	}

	if started.IsZero() {
		started = time.Now().UTC()
	}
	if completed.IsZero() {
		completed = started
	}

	findings := make([]json.RawMessage, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// Buffer can handle reasonably large lines up to 1MB per finding
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lineNum++
		if len(findings) >= maxNucleiFindings {
			return Result{}, fmt.Errorf("%w: Nuclei finding count exceeds limit", ErrMalformedOutput)
		}

		var entry nucleiJSONLEntry
		dec := json.NewDecoder(bytes.NewReader(line))
		if err := dec.Decode(&entry); err != nil {
			return Result{}, fmt.Errorf("%w: line %d is not valid JSON: %v", ErrMalformedOutput, lineNum, err)
		}

		finding, include, err := nucleiEntryFinding(entry, target.Hostname(), scannerVersion, started)
		if err != nil {
			return Result{}, fmt.Errorf("%w: invalid Nuclei record on line %d: %v", ErrMalformedOutput, lineNum, err)
		}
		if include {
			findings = append(findings, finding)
		}
	}

	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("%w: error reading Nuclei output: %v", ErrMalformedOutput, err)
	}

	catVerJSON, _ := json.Marshal(templateCatalogVersion)
	catDigestJSON, _ := json.Marshal(templateCatalogDigest)
	result := Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID:           task.AssessmentID,
			ScannerID:              ScannerNuclei,
			ScannerVersion:         scannerVersion,
			AdapterVersion:         "1.0.0",
			TemplateCatalogVersion: templateCatalogVersion,
			TemplateCatalogDigest:  templateCatalogDigest,
			RunID:                  uuid.NewString(),
			StartedAt:              started,
			CompletedAt:            completed,
			CorrelationID:          task.CorrelationID,
		},
		Status:          StatusCompleted,
		ExitCode:        intPointer(0),
		DurationMS:      completed.Sub(started).Milliseconds(),
		Findings:        findings,
		Diagnostics:     []ExecutionDiagnostic{},
		RawArtifacts:    RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{"nuclei.template_catalog_version": catVerJSON, "nuclei.template_catalog_digest": catDigestJSON},
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: normalized Nuclei output is invalid: %v", ErrMalformedOutput, err)
	}
	return result, nil
}

func nucleiEntryFinding(entry nucleiJSONLEntry, asset, scannerVersion string, discovered time.Time) (json.RawMessage, bool, error) {
	title := nucleiPlainText(entry.Info.Name, 500)
	if title == "" {
		title = nucleiPlainText(entry.TemplateID, 500)
	}
	if title == "" {
		return nil, false, fmt.Errorf("finding title and template ID are empty")
	}

	sevMap := map[string]string{
		"info":          "INFORMATIONAL",
		"informational": "INFORMATIONAL",
		"low":           "LOW",
		"medium":        "MEDIUM",
		"high":          "HIGH",
		"critical":      "CRITICAL",
	}
	severity, ok := sevMap[strings.ToLower(strings.TrimSpace(entry.Info.Severity))]
	if !ok {
		return nil, false, fmt.Errorf("unsupported Nuclei severity %q", entry.Info.Severity)
	}

	// Confidence mapping
	conf := 0.7
	switch severity {
	case "CRITICAL":
		conf = 0.95
	case "HIGH":
		conf = 0.85
	case "MEDIUM":
		conf = 0.7
	case "LOW":
		conf = 0.6
	case "INFORMATIONAL":
		conf = 0.5
	}

	templateID := strings.ToLower(strings.TrimSpace(entry.TemplateID))
	vulnerability := map[string]any{}
	if templateID != "" {
		vulnerability["template_id"] = templateID
	}
	if len(entry.Info.Classification.CWEID) > 0 {
		cwe := strings.TrimSpace(entry.Info.Classification.CWEID[0])
		if !strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
			cwe = "CWE-" + cwe
		}
		vulnerability["cwe_id"] = cwe
	}
	if len(entry.Info.Classification.CVEID) > 0 {
		var cves []string
		for _, cve := range entry.Info.Classification.CVEID {
			cve = strings.ToUpper(strings.TrimSpace(cve))
			if strings.HasPrefix(cve, "CVE-") {
				cves = append(cves, cve)
			}
		}
		if len(cves) > 0 {
			vulnerability["cve_ids"] = cves
		}
	}
	if entry.Info.Classification.CVSSScore > 0 {
		vulnerability["cvss"] = map[string]any{
			"version": "3.1",
			"score":   entry.Info.Classification.CVSSScore,
		}
	}

	metadata := map[string]any{}
	if templateID != "" {
		metadata["nuclei.template_id"] = templateID
	}
	if entry.MatcherName != "" {
		metadata["nuclei.matcher_name"] = nucleiPlainText(entry.MatcherName, 128)
	}
	metadata["kelvin.severity_native"] = strings.ToLower(strings.TrimSpace(entry.Info.Severity))

	finding := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       severity,
		"confidence":     conf,
		"target":         map[string]string{"asset": asset},
		"vulnerability":  vulnerability,
		"description":    nucleiPlainText(entry.Info.Description, 8192),
		"remediation":    map[string]any{"summary": "Review the identified template match and remediate according to vendor guidelines."},
		"evidence": []map[string]any{
			{
				"type":             "LOG",
				"content_type":     "text/plain",
				"content_redacted": nucleiPlainText(title, 2048),
				"size_bytes":       len(title),
				"redacted_fields":  []string{"request_headers", "response_body", "matched_at_url"},
			},
		},
		"scanner":      map[string]string{"name": ScannerNuclei, "adapter_version": "1.0.0", "engine_version": scannerVersion},
		"scanner_meta": metadata,
		"discovered_at": discovered.UTC().Format(time.RFC3339Nano),
	}

	encoded, err := json.Marshal(finding)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

func nucleiPlainText(raw string, limit int) string {
	text := html.UnescapeString(raw)
	text = nucleiURLQuery.ReplaceAllString(text, `${1}?[REDACTED]`)
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		text = text[:limit]
	}
	return text
}
