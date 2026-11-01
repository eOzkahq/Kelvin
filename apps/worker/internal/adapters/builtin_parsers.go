package adapters

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

// BuiltinCheckType represents the category of Kelvin native assessment checks.
type BuiltinCheckType string

const (
	BuiltinCheckPreflight BuiltinCheckType = "http_preflight"
	BuiltinCheckHeaders   BuiltinCheckType = "http_headers"
	BuiltinCheckTLS       BuiltinCheckType = "tls_assessment"
)

// BuiltinEvidence represents normalized structured evidence for built-in checks.
type BuiltinEvidence struct {
	Type            string   `json:"type"`
	ContentType     string   `json:"content_type"`
	ContentRedacted string   `json:"content_redacted"`
	Size            int      `json:"size_bytes,omitempty"`
	RedactedFields  []string `json:"redacted_fields"`
}

// NormalizeBuiltinPreflightResult normalizes HTTP/HTTPS preflight probe outcomes into Kelvin's canonical envelope.
// Preflight is purely a connectivity and environment probe; inconclusive checks or connection drops
// produce diagnostics, NEVER false-positive vulnerability findings.
func NormalizeBuiltinPreflightResult(task Task, obs preflightObservation, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerHTTPPreflight {
		return Result{}, fmt.Errorf("adapters: task scanner must be %s", ScannerHTTPPreflight)
	}

	metadataJSON, err := json.Marshal(obs)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: marshal preflight observation: %w", err)
	}

	status := StatusCompleted
	diagnostics := make([]ExecutionDiagnostic, 0)
	var exitCode *int
	zero := 0

	if obs.Outcome != "HTTP_RESPONDED" {
		status = StatusCompletedWithWarnings
		exitCode = &zero
		code := "TARGET_UNREACHABLE"
		message := "HTTP preflight could not obtain an HTTP response"
		if obs.Error != "" {
			switch obs.Error {
			case "timeout":
				status = StatusTimedOut
				code = "DEADLINE_EXCEEDED"
				message = "HTTP preflight request exceeded timeout"
				exitCode = nil
			case "cancelled":
				status = StatusCancelled
				code = "CANCELLED"
				message = "HTTP preflight request was cancelled"
				exitCode = nil
			default:
				code = strings.ToUpper(obs.Error)
				message = fmt.Sprintf("HTTP preflight failed: %s", obs.Error)
			}
		}
		level := "warning"
		if status == StatusTimedOut || status == StatusCancelled {
			level = "error"
		}
		diagnostics = append(diagnostics, ExecutionDiagnostic{
			Level:   level,
			Code:    code,
			Message: message,
		})
	} else {
		exitCode = &zero
	}

	res := Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID:  task.AssessmentID,
			ScannerID:     ScannerHTTPPreflight,
			ScannerVersion: "1.0.0",
			AdapterVersion: "1.0.0",
			RunID:         uuid.NewString(),
			StartedAt:     started,
			CompletedAt:   completed,
			CorrelationID: task.CorrelationID,
		},
		Status:       status,
		ExitCode:     exitCode,
		DurationMS:   completed.Sub(started).Milliseconds(),
		Findings:     []json.RawMessage{}, // Invariant: Preflight never produces findings
		Diagnostics:  diagnostics,
		RawArtifacts: RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{
			"http_preflight.observation": metadataJSON,
		},
	}

	if err := res.Validate(); err != nil {
		return Result{}, fmt.Errorf("adapters: normalized preflight result invalid: %w", err)
	}
	return res, nil
}

// NormalizeBuiltinHeadersResult normalizes response security header and cookie findings.
// Inconclusive connections (e.g. timeout, unreachable host) MUST NOT emit findings.
func NormalizeBuiltinHeadersResult(task Task, obs httpHeadersObservation, rawFindings []json.RawMessage, diagnostics []ExecutionDiagnostic, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerHTTPHeaders {
		return Result{}, fmt.Errorf("adapters: task scanner must be %s", ScannerHTTPHeaders)
	}

	if diagnostics == nil {
		diagnostics = make([]ExecutionDiagnostic, 0)
	}
	validatedFindings := make([]json.RawMessage, 0, len(rawFindings))

	// Inconclusive check enforcement: If the target failed to connect, drop any speculative findings
	if obs.Outcome != "HTTP_RESPONDED" && obs.Outcome != "" {
		validatedFindings = []json.RawMessage{}
		if len(diagnostics) == 0 {
			diagnostics = append(diagnostics, ExecutionDiagnostic{
				Level:   "warning",
				Code:    "HEADERS_CHECK_INCONCLUSIVE",
				Message: fmt.Sprintf("Security headers check inconclusive: %s", obs.Error),
			})
		}
	} else {
		for i, fRaw := range rawFindings {
			if err := parserguard.ValidatePayload(fRaw); err != nil {
				return Result{}, fmt.Errorf("adapters: header finding %d invalid payload: %w", i, err)
			}
			if err := ValidateFindings(fRaw); err != nil {
				return Result{}, fmt.Errorf("adapters: header finding %d schema validation failed: %w", i, err)
			}

			// Validate rule ID namespace
			var f map[string]any
			if err := json.Unmarshal(fRaw, &f); err == nil {
				if vuln, ok := f["vulnerability"].(map[string]any); ok {
					tmplID, _ := vuln["template_id"].(string)
					if !strings.HasPrefix(tmplID, "kelvin.http_headers.") {
						return Result{}, fmt.Errorf("adapters: invalid header rule ID %q", tmplID)
					}
				}
			}
			validatedFindings = append(validatedFindings, fRaw)
		}
	}

	status := StatusCompleted
	for _, d := range diagnostics {
		if d.Level == "warning" {
			status = StatusCompletedWithWarnings
		} else if d.Level == "error" {
			if d.Code == "DEADLINE_EXCEEDED" {
				status = StatusTimedOut
			} else if d.Code == "CANCELLED" {
				status = StatusCancelled
			} else {
				status = StatusFailed
			}
		}
	}

	obsJSON, _ := json.Marshal(obs)
	zero := 0
	res := Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID:  task.AssessmentID,
			ScannerID:     ScannerHTTPHeaders,
			ScannerVersion: "1.0.0",
			AdapterVersion: "1.0.0",
			RunID:         uuid.NewString(),
			StartedAt:     started,
			CompletedAt:   completed,
			CorrelationID: task.CorrelationID,
		},
		Status:       status,
		ExitCode:     &zero,
		DurationMS:   completed.Sub(started).Milliseconds(),
		Findings:     validatedFindings,
		Diagnostics:  diagnostics,
		RawArtifacts: RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{
			"http_headers.observation":       obsJSON,
			"http_headers.rule_set_version": json.RawMessage(`"` + HTTPHeaderRuleSetVersion + `"`),
		},
	}

	if err := res.Validate(); err != nil {
		return Result{}, fmt.Errorf("adapters: normalized headers result invalid: %w", err)
	}
	return res, nil
}

// NormalizeBuiltinTLSResult normalizes TLS configuration, certificate, and protocol findings.
// Inconclusive connections (e.g. connection refused, handshake failure) MUST NOT emit false-positive findings.
func NormalizeBuiltinTLSResult(task Task, obs tlsObservation, rawFindings []json.RawMessage, diagnostics []ExecutionDiagnostic, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerTLSAssessor {
		return Result{}, fmt.Errorf("adapters: task scanner must be %s", ScannerTLSAssessor)
	}

	if diagnostics == nil {
		diagnostics = make([]ExecutionDiagnostic, 0)
	}
	validatedFindings := make([]json.RawMessage, 0, len(rawFindings))

	// Inconclusive check enforcement: If handshake or connection failed, do not emit confirmed findings
	if obs.Outcome == "TLS_FAILED" || obs.Outcome == "UNREACHABLE" {
		validatedFindings = []json.RawMessage{}
		if len(diagnostics) == 0 {
			diagnostics = append(diagnostics, ExecutionDiagnostic{
				Level:   "warning",
				Code:    "TLS_CHECK_INCONCLUSIVE",
				Message: fmt.Sprintf("TLS assessment inconclusive: %s", obs.Error),
			})
		}
	} else {
		for i, fRaw := range rawFindings {
			if err := parserguard.ValidatePayload(fRaw); err != nil {
				return Result{}, fmt.Errorf("adapters: TLS finding %d invalid payload: %w", i, err)
			}
			if err := ValidateFindings(fRaw); err != nil {
				return Result{}, fmt.Errorf("adapters: TLS finding %d schema validation failed: %w", i, err)
			}

			// Validate rule ID namespace
			var f map[string]any
			if err := json.Unmarshal(fRaw, &f); err == nil {
				if vuln, ok := f["vulnerability"].(map[string]any); ok {
					tmplID, _ := vuln["template_id"].(string)
					if !strings.HasPrefix(tmplID, "kelvin.tls.") {
						return Result{}, fmt.Errorf("adapters: invalid TLS rule ID %q", tmplID)
					}
				}
			}
			validatedFindings = append(validatedFindings, fRaw)
		}
	}

	status := StatusCompleted
	for _, d := range diagnostics {
		if d.Level == "warning" {
			status = StatusCompletedWithWarnings
		} else if d.Level == "error" {
			if d.Code == "DEADLINE_EXCEEDED" {
				status = StatusTimedOut
			} else if d.Code == "CANCELLED" {
				status = StatusCancelled
			} else {
				status = StatusFailed
			}
		}
	}

	obsJSON, _ := json.Marshal(obs)
	zero := 0
	res := Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID:  task.AssessmentID,
			ScannerID:     ScannerTLSAssessor,
			ScannerVersion: "1.0.0",
			AdapterVersion: "1.0.0",
			RunID:         uuid.NewString(),
			StartedAt:     started,
			CompletedAt:   completed,
			CorrelationID: task.CorrelationID,
		},
		Status:       status,
		ExitCode:     &zero,
		DurationMS:   completed.Sub(started).Milliseconds(),
		Findings:     validatedFindings,
		Diagnostics:  diagnostics,
		RawArtifacts: RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{
			"tls_assessment.observation":      obsJSON,
			"tls_assessment.rule_set_version": json.RawMessage(`"` + TLSRuleSetVersion + `"`),
		},
	}

	if err := res.Validate(); err != nil {
		return Result{}, fmt.Errorf("adapters: normalized TLS result invalid: %w", err)
	}
	return res, nil
}

// BuildBuiltinFinding constructs a canonical finding map for built-in checks with validated structure and evidence.
func BuildBuiltinFinding(scannerName, host, endpoint, ruleID, title, severity, description, remediation string, confidence float64, evidence []BuiltinEvidence, tags []string, discovered time.Time) (json.RawMessage, error) {
	if !strings.HasPrefix(ruleID, "kelvin.") {
		return nil, fmt.Errorf("adapters: built-in finding rule ID must start with kelvin. prefix: %s", ruleID)
	}

	cleanHost := strings.TrimSpace(host)
	if cleanHost == "" {
		return nil, fmt.Errorf("adapters: target host must not be empty")
	}

	cleanEndpoint := cleanHost
	if endpoint != "" {
		if u, err := url.Parse(endpoint); err == nil {
			u.RawQuery = ""
			u.ForceQuery = false
			u.Fragment = ""
			cleanEndpoint = u.String()
		}
	}

	evList := make([]map[string]any, 0, len(evidence))
	for _, ev := range evidence {
		redactedFields := ev.RedactedFields
		if redactedFields == nil {
			redactedFields = []string{}
		}
		evMap := map[string]any{
			"type":             ev.Type,
			"content_type":     ev.ContentType,
			"content_redacted": ev.ContentRedacted,
			"size_bytes":       len(ev.ContentRedacted),
			"redacted_fields":  redactedFields,
		}
		evList = append(evList, evMap)
	}

	finding := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       severity,
		"confidence":     confidence,
		"target": map[string]any{
			"asset":    cleanHost,
			"endpoint": cleanEndpoint,
		},
		"vulnerability": map[string]any{
			"template_id": ruleID,
		},
		"description": description,
		"remediation": map[string]any{
			"summary": remediation,
		},
		"evidence": evList,
		"scanner": map[string]any{
			"name":            scannerName,
			"adapter_version": "1.0.0",
		},
		"discovered_at": discovered.UTC().Format(time.RFC3339Nano),
		"tags":          tags,
	}

	raw, err := json.Marshal(finding)
	if err != nil {
		return nil, err
	}
	if err := ValidateFindings(raw); err != nil {
		return nil, fmt.Errorf("adapters: invalid constructed finding: %w", err)
	}
	return raw, nil
}
