package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxZAPReportBytes = 4 << 20
const maxZAPAlerts = 10000

var zapHTMLTag = regexp.MustCompile(`<[^>]*>`)
var zapURLQuery = regexp.MustCompile(`(?i)(https?://[^?\s<>]+)\?[^\s<>]+`)

type zapReport struct {
	Version string `json:"@version"`
	Sites   []struct {
		Alerts []struct {
			PluginID   string `json:"pluginid"`
			Alert      string `json:"alert"`
			RiskCode   string `json:"riskcode"`
			Confidence string `json:"confidence"`
			Desc       string `json:"desc"`
			Solution   string `json:"solution"`
			CWEID      string `json:"cweid"`
		} `json:"alerts"`
	} `json:"site"`
}

// NormalizeZAPReport converts the bounded ZAP Baseline JSON report into
// Kelvin's output envelope. Target identity comes from the validated task,
// never from scanner-controlled report fields. Instance URLs and raw evidence
// are deliberately omitted because they may contain secrets or out-of-scope
// locations.
func NormalizeZAPReport(task Task, raw []byte, scannerVersion string, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerZAPBaseline || scannerVersion == "" || !started.IsZero() && completed.Before(started) {
		return Result{}, fmt.Errorf("adapters: invalid ZAP report context")
	}
	if len(raw) == 0 || len(raw) > maxZAPReportBytes {
		return Result{}, fmt.Errorf("adapters: ZAP report is empty or exceeds %d bytes", maxZAPReportBytes)
	}
	var report zapReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&report); err != nil {
		return Result{}, fmt.Errorf("%w: decode ZAP report: %v", ErrMalformedOutput, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Result{}, fmt.Errorf("%w: ZAP report contains trailing data", ErrMalformedOutput)
	}
	if len(report.Sites) == 0 || len(report.Sites) > 32 {
		return Result{}, fmt.Errorf("%w: ZAP report site count is invalid", ErrMalformedOutput)
	}
	if report.Version != scannerVersion {
		return Result{}, fmt.Errorf("%w: report version does not match verified ZAP runtime", ErrMalformedOutput)
	}
	if started.IsZero() {
		started = time.Now().UTC()
	}
	if completed.IsZero() {
		completed = started
	}
	profileVersion, _ := json.Marshal(ZAPSafetyProfileVersion)
	target, err := url.Parse(task.Target)
	if err != nil || target.Hostname() == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return Result{}, fmt.Errorf("adapters: ZAP task target is invalid")
	}
	findings := make([]json.RawMessage, 0)
	for _, site := range report.Sites {
		if len(site.Alerts) > maxZAPAlerts-len(findings) {
			return Result{}, fmt.Errorf("%w: ZAP report alert count exceeds limit", ErrMalformedOutput)
		}
		for _, alert := range site.Alerts {
			finding, include, err := zapAlertFinding(alert.PluginID, alert.Alert, alert.RiskCode, alert.Confidence, alert.Desc, alert.Solution, alert.CWEID, target.Hostname(), scannerVersion, started)
			if err != nil {
				return Result{}, fmt.Errorf("%w: invalid ZAP alert: %v", ErrMalformedOutput, err)
			}
			if include {
				findings = append(findings, finding)
			}
		}
	}
	result := Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata:      OutputMetadata{AssessmentID: task.AssessmentID, ScannerID: ScannerZAPBaseline, ScannerVersion: scannerVersion, AdapterVersion: "1.0.0", RunID: uuid.NewString(), StartedAt: started, CompletedAt: completed, CorrelationID: task.CorrelationID},
		Status:        StatusCompleted, ExitCode: intPointer(0), DurationMS: completed.Sub(started).Milliseconds(),
		Findings: findings, Diagnostics: []ExecutionDiagnostic{}, RawArtifacts: RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{"zap.safety_profile": profileVersion},
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: normalized ZAP output is invalid: %v", ErrMalformedOutput, err)
	}
	return result, nil
}

func zapAlertFinding(pluginID, title, riskCode, confidence, description, solution, cweID, asset, scannerVersion string, discovered time.Time) (json.RawMessage, bool, error) {
	title = zapPlainText(title, 500)
	if title == "" {
		return nil, false, fmt.Errorf("alert title is empty")
	}
	severity, include := map[string]string{"0": "INFORMATIONAL", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}[riskCode]
	if severity == "" {
		return nil, false, fmt.Errorf("unsupported risk code %q", riskCode)
	}
	if !include {
		return nil, false, nil
	}
	conf := 0.5
	switch strings.ToLower(confidence) {
	case "high":
		conf = 0.9
	case "medium":
		conf = 0.7
	case "low":
		conf = 0.5
	case "false positive":
		conf = 0.2
	default:
		if _, err := strconv.Atoi(confidence); err == nil {
			return nil, false, fmt.Errorf("numeric confidence is unsupported")
		}
	}
	metadata := map[string]any{}
	if pluginID != "" && len(pluginID) <= 64 {
		metadata["zap.plugin_id"] = pluginID
	}
	if len(metadata) == 0 {
		return nil, false, fmt.Errorf("alert plugin ID is missing")
	}
	var vulnerability map[string]string
	if n, err := strconv.Atoi(cweID); err == nil && n > 0 && n <= 999999 {
		vulnerability = map[string]string{"cwe_id": fmt.Sprintf("CWE-%d", n)}
	} else {
		vulnerability = map[string]string{}
	}
	finding := map[string]any{
		"schema_version": "1.0", "title": title, "severity": severity, "confidence": conf,
		"target": map[string]string{"asset": asset}, "vulnerability": vulnerability,
		"description":  zapPlainText(description, 8192),
		"remediation":  map[string]any{"summary": zapPlainText(solution, 4096)},
		"evidence":     []map[string]any{{"type": "LOG", "content_type": "text/plain", "content_redacted": title, "size_bytes": len(title), "redacted_fields": []string{"scanner_instance_urls"}}},
		"scanner":      map[string]string{"name": ScannerZAPBaseline, "adapter_version": "1.0.0", "engine_version": scannerVersion},
		"scanner_meta": metadata, "discovered_at": discovered.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		return nil, false, err
	}
	// run_id is assigned by the output envelope; finding schema accepts it as
	// an optional scanner value but we don't duplicate envelope identifiers.
	return encoded, true, nil
}

func zapPlainText(raw string, limit int) string {
	text := html.UnescapeString(zapHTMLTag.ReplaceAllString(raw, " "))
	text = zapURLQuery.ReplaceAllString(text, `${1}?[REDACTED]`)
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		text = text[:limit]
	}
	return text
}
