package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

const maxNucleiReportBytes = 4 << 20
const maxNucleiFindings = 10000

var nucleiURLQuery = regexp.MustCompile(`(?i)(https?://[^?\s<>]+)\?[^\s<>]+`)

// stringOrSlice handles fields that can be either a string or a slice of strings.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single != "" {
			*s = []string{single}
		}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*s = multi
		return nil
	}
	return nil
}

type nucleiJSONLEntry struct {
	TemplateID  string `json:"template-id"`
	TemplateURL string `json:"template-url,omitempty"`
	Info        struct {
		Name           string        `json:"name"`
		Author         any           `json:"author,omitempty"`
		Tags           stringOrSlice `json:"tags,omitempty"`
		Description    string        `json:"description,omitempty"`
		Reference      any           `json:"reference,omitempty"`
		Severity       string        `json:"severity"`
		Classification struct {
			CVSSScore float64       `json:"cvss-score,omitempty"`
			CVEID     stringOrSlice `json:"cve-id,omitempty"`
			CWEID     stringOrSlice `json:"cwe-id,omitempty"`
		} `json:"classification,omitempty"`
	} `json:"info"`
	Type             string        `json:"type,omitempty"`
	Host             string        `json:"host,omitempty"`
	MatchedAt        string        `json:"matched-at,omitempty"`
	ExtractedResults stringOrSlice `json:"extracted-results,omitempty"`
	Request          string        `json:"request,omitempty"`
	Response         string        `json:"response,omitempty"`
	IP               string        `json:"ip,omitempty"`
	Timestamp        string        `json:"timestamp,omitempty"`
	CurlCommand      string        `json:"curl-command,omitempty"`
	MatcherName      string        `json:"matcher-name,omitempty"`
}

// NormalizeNucleiReport converts bounded Nuclei JSONL output into
// Kelvin's output envelope. Target identity comes from the validated task,
// never from scanner-controlled report fields. Raw request/response and URLs
// are sanitized, scope-checked, and strictly bound.
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

	if len(raw) > 0 {
		if err := parserguard.ValidatePayload(raw); err != nil {
			return Result{}, fmt.Errorf("%w: invalid Nuclei payload: %v", ErrMalformedOutput, err)
		}
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
	diagnostics := make([]ExecutionDiagnostic, 0)
	lineNum := 0

	err = parserguard.ScanBoundedLines(bytes.NewReader(raw), parserguard.MaxLineBytes, func(line []byte) error {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			return nil
		}
		lineNum++
		if len(findings) >= maxNucleiFindings {
			return fmt.Errorf("%w: Nuclei finding count exceeds limit", ErrMalformedOutput)
		}

		if err := parserguard.CheckJSONNestingDepth(trimmed, parserguard.MaxNestingDepth); err != nil {
			return fmt.Errorf("%w: line %d nesting depth exceeded: %v", ErrMalformedOutput, lineNum, err)
		}

		var entry nucleiJSONLEntry
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(&entry); err != nil {
			return fmt.Errorf("%w: line %d is not valid JSON: %v", ErrMalformedOutput, lineNum, err)
		}

		if isProhibitedOrOutOfScope(entry.MatchedAt, target.Hostname()) {
			diagnostics = append(diagnostics, ExecutionDiagnostic{
				Level:   "warning",
				Code:    "NUCLEI_OUT_OF_SCOPE_TARGET",
				Message: fmt.Sprintf("Line %d reported target %s outside authorized asset %s", lineNum, entry.MatchedAt, target.Hostname()),
			})
		}

		finding, include, err := nucleiEntryFinding(entry, target.Hostname(), scannerVersion, started)
		if err != nil {
			return fmt.Errorf("%w: invalid Nuclei record on line %d: %v", ErrMalformedOutput, lineNum, err)
		}
		if include {
			findings = append(findings, finding)
		}
		return nil
	})

	if err != nil {
		return Result{}, err
	}

	catVerJSON, _ := json.Marshal(templateCatalogVersion)
	catDigestJSON, _ := json.Marshal(templateCatalogDigest)

	status := StatusCompleted
	for _, d := range diagnostics {
		if d.Level == "warning" {
			status = StatusCompletedWithWarnings
			break
		}
	}

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
		Status:          status,
		ExitCode:        intPointer(0),
		DurationMS:      completed.Sub(started).Milliseconds(),
		Findings:        findings,
		Diagnostics:     diagnostics,
		RawArtifacts:    RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{
			"nuclei.template_catalog_version": catVerJSON,
			"nuclei.template_catalog_digest":  catDigestJSON,
			"nuclei.parser_version":           json.RawMessage(`"1.0.0"`),
		},
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

	metadata := map[string]any{
		"nuclei.parser_version": "1.0.0",
	}
	if templateID != "" {
		metadata["nuclei.template_id"] = templateID
	}
	if entry.MatcherName != "" {
		metadata["nuclei.matcher_name"] = nucleiPlainText(entry.MatcherName, 128)
	}
	if entry.Type != "" {
		metadata["nuclei.type"] = nucleiPlainText(entry.Type, 64)
	}
	if len(entry.ExtractedResults) > 0 {
		cleanResults := make([]string, 0, len(entry.ExtractedResults))
		for _, r := range entry.ExtractedResults {
			clean := nucleiPlainText(r, 256)
			if clean != "" {
				cleanResults = append(cleanResults, clean)
			}
		}
		if len(cleanResults) > 0 {
			metadata["nuclei.extracted_results"] = cleanResults
		}
	}
	metadata["kelvin.severity_native"] = strings.ToLower(strings.TrimSpace(entry.Info.Severity))

	evidenceList := []map[string]any{
		{
			"type":             "LOG",
			"content_type":     "text/plain",
			"content_redacted": nucleiPlainText(title, 2048),
			"size_bytes":       len(title),
			"redacted_fields":  []string{"request_headers", "response_body", "matched_at_url"},
		},
	}

	if entry.CurlCommand != "" {
		sanitizedCurl := nucleiPlainText(entry.CurlCommand, 2048)
		evidenceList = append(evidenceList, map[string]any{
			"type":             "LOG",
			"content_type":     "text/plain",
			"content_redacted": sanitizedCurl,
			"size_bytes":       len(sanitizedCurl),
			"redacted_fields":  []string{"curl_command_args"},
		})
	}

	finding := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       severity,
		"confidence":     conf,
		"target":         map[string]string{"asset": asset},
		"vulnerability":  vulnerability,
		"description":    nucleiPlainText(entry.Info.Description, 8192),
		"remediation":    map[string]any{"summary": "Review the identified template match and remediate according to vendor guidelines."},
		"evidence":       evidenceList,
		"scanner": map[string]string{
			"name":            ScannerNuclei,
			"adapter_version": "1.0.0",
			"engine_version":  scannerVersion,
		},
		"scanner_meta":  metadata,
		"discovered_at": discovered.UTC().Format(time.RFC3339Nano),
	}

	encoded, err := json.Marshal(finding)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

func isProhibitedOrOutOfScope(matchedAt, approvedHostname string) bool {
	if matchedAt == "" {
		return false
	}
	u, err := url.Parse(matchedAt)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "169.254.169.254" || host == "metadata.google.internal" || host == "127.0.0.1" || host == "localhost" {
		return true
	}
	approved := strings.ToLower(approvedHostname)
	if host != approved && !strings.HasSuffix(host, "."+approved) {
		return true
	}
	return false
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
