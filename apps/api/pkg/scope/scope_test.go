package scope

import (
	"errors"
	"net/http"
	"testing"
)

func TestScopeProblemIs422(t *testing.T) {
	problem := Problem(errors.Join(ErrProhibited, errors.New("private address")))
	if problem.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", problem.Status)
	}
	if problem.Type != "urn:kelvin:problem:target_scope_violation" {
		t.Fatalf("type=%q", problem.Type)
	}
	if problem.Detail == "private address" {
		t.Fatal("internal validation detail leaked")
	}
}
