package adapters

import (
	"testing"
	"time"
)

func validTask() Task {
	return Task{
		JobID:         "11111111-1111-1111-1111-111111111111",
		AssessmentID:  "22222222-2222-2222-2222-222222222222",
		TenantID:      "33333333-3333-3333-3333-333333333333",
		CorrelationID: "corr-1",
		Scanner:       "nuclei",
		Target:        "example.com",
		ProfileID:     "kelvin.profile.standard.v1",
		HardDeadline:  10 * time.Minute,
		Payload:       []byte(`{}`),
	}
}

func TestValidateTaskAcceptsValidTask(t *testing.T) {
	if err := ValidateTask(validTask()); err != nil {
		t.Fatalf("valid task should pass: %v", err)
	}
}

func TestValidateTaskRejectsEmptyIDs(t *testing.T) {
	cases := []struct {
		name string
		task Task
	}{
		{"empty job_id", Task{AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: "n", Target: "t", ProfileID: "p", HardDeadline: time.Minute}},
		{"empty assessment_id", Task{JobID: "11111111-1111-1111-1111-111111111111", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: "n", Target: "t", ProfileID: "p", HardDeadline: time.Minute}},
		{"empty tenant_id", Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", Scanner: "n", Target: "t", ProfileID: "p", HardDeadline: time.Minute}},
		{"empty scanner", Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Target: "t", ProfileID: "p", HardDeadline: time.Minute}},
		{"empty target", Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: "n", ProfileID: "p", HardDeadline: time.Minute}},
		{"empty profile_id", Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: "n", Target: "t", HardDeadline: time.Minute}},
		{"zero deadline", Task{JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222", TenantID: "33333333-3333-3333-3333-333333333333", Scanner: "n", Target: "t", ProfileID: "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateTask(tc.task); err == nil {
				t.Errorf("expected validation failure for %s", tc.name)
			}
		})
	}
}

func TestValidateTaskRejectsNonUUID(t *testing.T) {
	task := validTask()
	task.JobID = "not-a-uuid"
	if err := ValidateTask(task); err == nil {
		t.Error("expected rejection for non-UUID job_id")
	}
	task = validTask()
	task.TenantID = "not-a-uuid"
	if err := ValidateTask(task); err == nil {
		t.Error("expected rejection for non-UUID tenant_id")
	}
}

func validFindings() []byte {
	return []byte(`{
		"schema_version": "1.0",
		"title": "example finding",
		"severity": "INFORMATIONAL",
		"confidence": 0.5,
		"target": {"asset": "example.com"},
		"vulnerability": {"template_id": "example-template"},
		"scanner": {"name": "stub", "adapter_version": "1.0.0"},
		"discovered_at": "2026-10-28T00:00:00Z"
	}`)
}

func TestValidateFindingsAcceptsValidFindings(t *testing.T) {
	if err := ValidateFindings(validFindings()); err != nil {
		t.Fatalf("valid findings should pass: %v", err)
	}
}

func TestValidateFindingsRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"not json", []byte(`not json`)},
		{"not an object", []byte(`[1,2,3]`)},
		{"unknown root field", []byte(`{"schema_version":"1.0","title":"t","severity":"INFORMATIONAL","confidence":0.5,"target":{"asset":"a"},"vulnerability":{},"scanner":{"name":"s","adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z","bogus":1}`)},
		{"missing severity", []byte(`{"schema_version":"1.0","title":"t","confidence":0.5,"target":{"asset":"a"},"vulnerability":{},"scanner":{"name":"s","adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z}`)},
		{"bad severity enum", []byte(`{"schema_version":"1.0","title":"t","severity":"INFO","confidence":0.5,"target":{"asset":"a"},"vulnerability":{},"scanner":{"name":"s","adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z}`)},
		{"confidence out of range", []byte(`{"schema_version":"1.0","title":"t","severity":"INFORMATIONAL","confidence":1.5,"target":{"asset":"a"},"vulnerability":{},"scanner":{"name":"s","adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z}`)},
		{"missing target.asset", []byte(`{"schema_version":"1.0","title":"t","severity":"INFORMATIONAL","confidence":0.5,"target":{},"vulnerability":{},"scanner":{"name":"s","adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z}`)},
		{"missing scanner.name", []byte(`{"schema_version":"1.0","title":"t","severity":"INFORMATIONAL","confidence":0.5,"target":{"asset":"a"},"vulnerability":{},"scanner":{"adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z}`)},
		{"bad schema_version", []byte(`{"schema_version":"2.0","title":"t","severity":"INFORMATIONAL","confidence":0.5,"target":{"asset":"a"},"vulnerability":{},"scanner":{"name":"s","adapter_version":"1.0.0"},"discovered_at":"2026-10-28T00:00:00Z}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateFindings(tc.raw); err == nil {
				t.Errorf("expected validation failure for %s", tc.name)
			}
		})
	}
}

func TestValidateFindingsToleratesNamespacedExtension(t *testing.T) {
	raw := []byte(`{
		"schema_version": "1.0",
		"title": "t",
		"severity": "INFORMATIONAL",
		"confidence": 0.5,
		"target": {"asset": "a"},
		"vulnerability": {},
		"scanner": {"name": "s", "adapter_version": "1.0.0"},
		"discovered_at": "2026-10-28T00:00:00Z",
		"scanner_meta": {"org.acme.severity_override": "high"}
	}`)
	if err := ValidateFindings(raw); err != nil {
		t.Fatalf("namespaced scanner_meta extension should be tolerated: %v", err)
	}
}
