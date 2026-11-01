// Package adapters defines the scanner adapter contract. Adapters execute
// scanner binaries inside the worker sandbox and return structured findings
// that are treated as untrusted input and validated before ingestion.
//
// See docs/architecture/EXECUTION_ISOLATION.md §5 for the normative contract.
package adapters

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

var (
	schemaVersionRe = regexp.MustCompile(`^1\.[0-9]+$`)
	severityRe      = regexp.MustCompile(`^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)$`)
)

// Task is the validated input to one scanner adapter execution. It is produced
// by the worker daemon from a dequeued job and contains only data that has
// already passed tenant-scope, profile, and target validation.
type Task struct {
	// JobID is the durable job identifier (UUID).
	JobID string
	// AssessmentID is the owning assessment (UUID).
	AssessmentID string
	// TenantID is the owning tenant (UUID); never empty.
	TenantID string
	// CorrelationID traces the request across platform components.
	CorrelationID string
	// Scanner is the registered adapter name (e.g. "nuclei", "nmap").
	Scanner string
	// Target is the scope-validated target host/URL to assess.
	Target string
	// ProfileID is the scan profile governing execution bounds.
	ProfileID string
	// HardDeadline is the absolute execution deadline derived from the scan
	// profile's hard_execution_deadline_seconds.
	HardDeadline time.Duration
	// Payload is scanner-specific input (raw JSON from the job envelope).
	Payload json.RawMessage
}

// ValidateTask fails closed on any malformed or untrusted task input.
func ValidateTask(t Task) error {
	if t.JobID == "" {
		return fmt.Errorf("adapters: task job_id must not be empty")
	}
	if _, err := uuid.Parse(t.JobID); err != nil {
		return fmt.Errorf("adapters: invalid job_id %q: %w", t.JobID, err)
	}
	if t.AssessmentID == "" {
		return fmt.Errorf("adapters: task assessment_id must not be empty")
	}
	if _, err := uuid.Parse(t.AssessmentID); err != nil {
		return fmt.Errorf("adapters: invalid assessment_id %q: %w", t.AssessmentID, err)
	}
	if t.TenantID == "" {
		return fmt.Errorf("adapters: task tenant_id must not be empty")
	}
	if _, err := uuid.Parse(t.TenantID); err != nil {
		return fmt.Errorf("adapters: invalid tenant_id %q: %w", t.TenantID, err)
	}
	if t.Scanner == "" {
		return fmt.Errorf("adapters: task scanner must not be empty")
	}
	if t.Target == "" {
		return fmt.Errorf("adapters: task target must not be empty")
	}
	if t.ProfileID == "" {
		return fmt.Errorf("adapters: task profile_id must not be empty")
	}
	if t.HardDeadline <= 0 {
		return fmt.Errorf("adapters: task hard_deadline must be positive")
	}
	return nil
}

// ValidateFindings performs structural validation of raw scanner findings
// against the canonical finding.v1.json schema. It is dependency-free and
// fails closed: unknown root fields, missing required fields, or out-of-range
// values cause rejection. Production ingestion should additionally validate
// against the full draft-2020-12 schema via a JSON Schema validator.
func ValidateFindings(raw []byte) error {
	if err := parserguard.ValidatePayload(raw); err != nil {
		return fmt.Errorf("adapters: %w", err)
	}
	if err := parserguard.CheckJSONNestingDepth(raw, parserguard.MaxNestingDepth); err != nil {
		return fmt.Errorf("adapters: %w", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("adapters: findings are not valid JSON: %w", err)
	}
	root, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("adapters: findings root must be a JSON object")
	}
	// Root fields not in the finding.v1.json schema are rejected
	// (additionalProperties: false), except the namespaced scanner_meta
	// extension point.
	allowedRoot := map[string]bool{
		"schema_version": true, "id": true, "fingerprint": true, "status": true,
		"title": true, "severity": true, "confidence": true, "target": true,
		"vulnerability": true, "description": true, "reproduction_steps": true,
		"remediation": true, "evidence": true, "scanner": true,
		"scanner_meta": true, "tags": true, "discovered_at": true,
	}
	for field := range root {
		if field == "scanner_meta" {
			continue // namespaced extension point; sub-keys validated by server
		}
		if !allowedRoot[field] {
			return fmt.Errorf("adapters: unknown root field %q in findings", field)
		}
	}
	// Required fields (server-assigned id/fingerprint/status are validated
	// server-side and ignored if supplied by the scanner).
	required := []string{"schema_version", "title", "severity", "confidence", "target", "vulnerability", "scanner", "discovered_at"}
	for _, field := range required {
		if _, present := root[field]; !present {
			return fmt.Errorf("adapters: missing required field %q in findings", field)
		}
	}
	if sv, ok := root["schema_version"].(string); !ok || !schemaVersionRe.MatchString(sv) {
		return fmt.Errorf("adapters: field schema_version must match ^1\\.[0-9]+$")
	}
	if sev, ok := root["severity"].(string); !ok || !severityRe.MatchString(sev) {
		return fmt.Errorf("adapters: field severity must be one of CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL")
	}
	if conf, ok := root["confidence"].(float64); !ok || conf < 0 || conf > 1 {
		return fmt.Errorf("adapters: field confidence must be a number in 0..1")
	}
	if target, ok := root["target"].(map[string]any); !ok {
		return fmt.Errorf("adapters: field target must be an object")
	} else if _, present := target["asset"]; !present {
		return fmt.Errorf("adapters: field target.asset is required")
	}
	if scanner, ok := root["scanner"].(map[string]any); !ok {
		return fmt.Errorf("adapters: field scanner must be an object")
	} else {
		if _, present := scanner["name"]; !present {
			return fmt.Errorf("adapters: field scanner.name is required")
		}
		if _, present := scanner["adapter_version"]; !present {
			return fmt.Errorf("adapters: field scanner.adapter_version is required")
		}
	}
	// discovered_at must be a non-empty string.
	if da, ok := root["discovered_at"].(string); !ok || da == "" {
		return fmt.Errorf("adapters: field discovered_at must be a non-empty string")
	}
	return nil
}
