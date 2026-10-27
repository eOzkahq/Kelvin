package errors

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestConstructorsCarryRegistryTypesAndStatuses(t *testing.T) {
	cases := []struct {
		err    *API
		typ    string
		status int
	}{
		{NewValidation([]FieldError{{Field: "name", Code: "required", Message: "is required"}}), ProblemValidationFailed, 422},
		{NewNotFound("assessment not found"), ProblemNotFound, 404},
		{NewForbidden("permission denied"), ProblemForbidden, 403},
		{NewConflict("idempotency key reused"), ProblemConflict, 409},
		{NewTargetScopeViolation("target is in a blocked range"), ProblemTargetScopeViolation, 422},
		{NewInternal(errors.New("boom")), ProblemInternalError, 500},
	}
	for _, c := range cases {
		if c.err.Type != c.typ {
			t.Errorf("type = %q, want %q", c.err.Type, c.typ)
		}
		if c.err.Status != c.status {
			t.Errorf("status = %d, want %d", c.err.Status, c.status)
		}
		if !strings.HasPrefix(c.err.Type, "urn:kelvin:problem:") {
			t.Errorf("type %q outside URN namespace", c.err.Type)
		}
	}
}

func TestProblemJSONMatchesWireContract(t *testing.T) {
	inner := errors.New("dial tcp 10.0.0.1:5432: connect: refused")
	apiErr := NewInternal(inner)
	raw, err := json.Marshal(apiErr.Problem("3f1c9a72-5d84-4e0b-9c6a-1b7e2d4f8a55", "/api/v1/health", "2026-10-27T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, "10.0.0.1") || strings.Contains(body, "dial tcp") {
		t.Fatalf("internal cause leaked into problem body: %s", body)
	}
	var problem Problem
	if err := json.Unmarshal(raw, &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Status != 500 || problem.CorrelationID == "" || problem.Timestamp == "" {
		t.Fatalf("missing mandatory members: %+v", problem)
	}
}

func TestUnwrapKeepsCauseForLogging(t *testing.T) {
	cause := errors.New("root cause")
	if !errors.Is(NewInternal(cause), cause) {
		t.Fatal("NewInternal must preserve the cause for the logging chain")
	}
	if NewInternal(cause).Unwrap() == nil {
		t.Fatal("Unwrap must expose the cause")
	}
}

func TestValidationProblemCarriesErrorsArray(t *testing.T) {
	p := NewValidation([]FieldError{{Field: "targets[0].host", Code: "invalid", Message: "not a valid host"}}).Problem("cid", "/api/v1/assessments", "2026-10-27T00:00:00Z")
	raw, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["errors"]; !ok {
		t.Fatalf("validation problem must include errors[]: %s", raw)
	}
}
