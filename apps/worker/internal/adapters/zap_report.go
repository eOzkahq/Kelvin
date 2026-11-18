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
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

const maxZAPReportBytes = 4 << 20
const maxZAPAlerts = 10000

var zapHTMLTag = regexp.MustCompile(`<[^>]*>`)
var zapURLQuery = regexp.MustCompile(`(?i)(https?://[^?\s<>]+)\?[^\s<>]+`)

type zapReport struct {
	Version   string `json:"@version"`
	Generated string `json:"@generated,omitempty"`
	Sites     []struct {
		Name   string        `json:"@name,omitempty"`
		Host   string        `json:"@host,omitempty"`
		Port   string        `json:"@port,omitempty"`
		Alerts []zapRawAlert `json:"alerts"`
	} `json:"site"`
}

type zapRawAlert struct {
	PluginID   string           `json:"pluginid"`
	Alert      string           `json:"alert"`
	RiskCode   string           `json:"riskcode"`
	Confidence string           `json:"confidence"`
	RiskDesc   string           `json:"riskdesc,omitempty"`
	Desc       string           `json:"desc"`
	Solution   string           `json:"solution"`
	OtherInfo  string           `json:"otherinfo,omitempty"`
	Reference  string           `json:"reference,omitempty"`
	CWEID      string           `json:"cweid"`
	WASCID     string           `json:"wascid,omitempty"`
	SourceID   string           `json:"sourceid,omitempty"`
	Instances  []zapRawInstance `json:"instances,omitempty"`
	Count      string           `json:"count,omitempty"`
}

type zapRawInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method,omitempty"`
	Param    string `json:"param,omitempty"`
	Attack   string `json:"attack,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// NormalizeZAPReport converts the bounded ZAP Baseline JSON report into
// Kelvin's output envelope. Target identity comes from the validated task,
// never from scanner-controlled report fields. Instance URLs and raw evidence
// are deliberately sanitized and redacted to prevent leaking secrets.
func NormalizeZAPReport(task Task, raw []byte, scannerVersion string, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerZAPBaseline || scannerVersion == "" || (!started.IsZero() && completed.Before(started)) {
		return Result{}, fmt.Errorf("adapters: invalid ZAP report context")
	}
	if len(raw) == 0 || len(raw) > maxZAPReportBytes {
		return Result{}, fmt.Errorf("adapters: ZAP report is empty or exceeds %d bytes", maxZAPReportBytes)
	}

	if err := parserguard.ValidatePayload(raw); err != nil {
		return Result{}, fmt.Errorf("%w: invalid ZAP report payload: %v", ErrMalformedOutput, err)
	}
	if err := parserguard.CheckJSONNestingDepth(raw, parserguard.MaxNestingDepth); err != nil {
		return Result{}, fmt.Errorf("%w: ZAP report nesting depth exceeded: %v", ErrMalformedOutput, err)
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
	if strings.TrimPrefix(report.Version, "v") != strings.TrimPrefix(scannerVersion, "v") {
		return Result{}, fmt.Errorf("%w: report version %q does not match verified ZAP runtime %q", ErrMalformedOutput, report.Version, scannerVersion)
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
			finding, include, err := zapAlertFinding(alert, target.Hostname(), scannerVersion, started)
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
		Metadata: OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      ScannerZAPBaseline,
			ScannerVersion: scannerVersion,
			AdapterVersion: "1.0.0",
			RunID:          uuid.NewString(),
			StartedAt:      started,
			CompletedAt:    completed,
			CorrelationID:  task.CorrelationID,
		},
		Status:        StatusCompleted,
		ExitCode:      intPointer(0),
		DurationMS:    completed.Sub(started).Milliseconds(),
		Findings:      findings,
		Diagnostics:   []ExecutionDiagnostic{},
		RawArtifacts:  RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{
			"zap.safety_profile": profileVersion,
			"zap.parser_version": json.RawMessage(`"1.0.0"`),
		},
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: normalized ZAP output is invalid: %v", ErrMalformedOutput, err)
	}
	return result, nil
}

func zapAlertFinding(alert zapRawAlert, asset, scannerVersion string, discovered time.Time) (json.RawMessage, bool, error) {
	title := zapPlainText(alert.Alert, 500)
	if title == "" {
		return nil, false, fmt.Errorf("alert title is empty")
	}
	severity, include := map[string]string{"0": "INFORMATIONAL", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}[alert.RiskCode]
	if severity == "" {
		return nil, false, fmt.Errorf("unsupported risk code %q", alert.RiskCode)
	}
	if !include {
		return nil, false, nil
	}

	conf := 0.5
	switch strings.ToLower(alert.Confidence) {
	case "high", "3":
		conf = 0.9
	case "medium", "2":
		conf = 0.7
	case "low", "1":
		conf = 0.5
	case "false positive", "0":
		conf = 0.2
	default:
		conf = 0.5
	}

	metadata := map[string]any{
		"zap.parser_version": "1.0.0",
	}
	if alert.PluginID != "" && len(alert.PluginID) <= 64 {
		metadata["zap.plugin_id"] = alert.PluginID
	} else {
		return nil, false, fmt.Errorf("alert plugin ID is missing")
	}
	if alert.SourceID != "" {
		metadata["zap.source_id"] = alert.SourceID
	}
	if alert.Count != "" {
		metadata["zap.alert_count"] = alert.Count
	}

	vulnerability := map[string]string{}
	if n, err := strconv.Atoi(alert.CWEID); err == nil && n > 0 && n <= 999999 {
		vulnerability["cwe_id"] = fmt.Sprintf("CWE-%d", n)
	}
	if n, err := strconv.Atoi(alert.WASCID); err == nil && n > 0 && n <= 999999 {
		vulnerability["wasc_id"] = fmt.Sprintf("WASC-%d", n)
	}

	evidenceList := make([]map[string]any, 0)
	evidenceList = append(evidenceList, map[string]any{
		"type":            "LOG",
		"content_type":    "text/plain",
		"content_redacted": title,
		"size_bytes":      len(title),
		"redacted_fields": []string{"scanner_instance_urls"},
	})

	finding := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       severity,
		"confidence":     conf,
		"target":         map[string]string{"asset": asset},
		"vulnerability":  vulnerability,
		"description":    zapPlainText(alert.Desc, 8192),
		"remediation":    map[string]any{"summary": zapPlainText(alert.Solution, 4096)},
		"evidence":       evidenceList,
		"scanner": map[string]string{
			"name":            ScannerZAPBaseline,
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

func zapPlainText(raw string, limit int) string {
	text := html.UnescapeString(zapHTMLTag.ReplaceAllString(raw, " "))
	text = zapURLQuery.ReplaceAllString(text, `${1}?[REDACTED]`)
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > limit {
		text = text[:limit]
	}
	return text
}
