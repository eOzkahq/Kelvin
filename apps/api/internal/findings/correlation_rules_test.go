package findings

import (
	"testing"

	"github.com/google/uuid"
)

func TestCommonCVERuleMatch(t *testing.T) {
	engine := NewDefaultCorrelationRuleEngine()
	tenantID := uuid.New()

	findingA := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Title:            "Apache Log4j RCE (Nuclei)",
		AffectedEndpoint: "https://auth.example.com/login",
		CVEIDs:           []string{"CVE-2021-44228"},
		CWEID:            "CWE-502",
		Severity:         "CRITICAL",
	}

	findingB := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Title:            "Log4Shell Remote Code Execution (ZAP)",
		AffectedEndpoint: "https://auth.example.com:443/oauth/token",
		CVEIDs:           []string{"CVE-2021-44228", "CVE-2021-45046"},
		CWEID:            "CWE-502",
		Severity:         "CRITICAL",
	}

	match := engine.EvaluatePair(findingA, findingB)
	if match == nil {
		t.Fatalf("expected correlation match on shared CVE")
	}

	if !match.Matched {
		t.Errorf("expected matched = true")
	}
	if match.RuleID != "RULE_COMMON_CVE" {
		t.Errorf("expected rule RULE_COMMON_CVE, got %s", match.RuleID)
	}
	if match.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", match.Confidence)
	}
	if match.CorrelationType != CorrelationCommonID {
		t.Errorf("expected type COMMON_IDENTIFIER, got %s", match.CorrelationType)
	}
}

func TestSameEndpointCWERuleMatch(t *testing.T) {
	engine := NewDefaultCorrelationRuleEngine()
	tenantID := uuid.New()

	findingA := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Title:            "Blind SQL Injection via Search Param",
		AffectedEndpoint: "https://shop.example.com/api/v1/search",
		CWEID:            "CWE-89",
		Severity:         "HIGH",
	}

	findingB := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Title:            "Time-based SQLi on Query Endpoint",
		AffectedEndpoint: "https://shop.example.com/api/v1/search",
		CWEID:            "CWE-89",
		Severity:         "HIGH",
	}

	match := engine.EvaluatePair(findingA, findingB)
	if match == nil {
		t.Fatalf("expected correlation match on identical endpoint + CWE")
	}

	if match.RuleID != "RULE_SAME_ENDPOINT_CWE" {
		t.Errorf("expected rule RULE_SAME_ENDPOINT_CWE, got %s", match.RuleID)
	}
	if match.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", match.Confidence)
	}
}

func TestHTTPHeaderBaselineRuleMatch(t *testing.T) {
	engine := NewDefaultCorrelationRuleEngine()
	tenantID := uuid.New()

	findingHSTS := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Title:            "Strict-Transport-Security Header Missing",
		AffectedEndpoint: "https://app.example.com/",
		CWEID:            "CWE-319",
		Severity:         "LOW",
	}

	findingCSP := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Title:            "Content-Security-Policy Header Not Set",
		AffectedEndpoint: "https://app.example.com/dashboard",
		CWEID:            "CWE-693",
		Severity:         "MEDIUM",
	}

	match := engine.EvaluatePair(findingHSTS, findingCSP)
	if match == nil {
		t.Fatalf("expected correlation match on HTTP security header baseline")
	}

	if match.RuleID != "RULE_HTTP_HEADER_BASELINE" {
		t.Errorf("expected rule RULE_HTTP_HEADER_BASELINE, got %s", match.RuleID)
	}
	if match.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %f", match.Confidence)
	}
}

func TestCorrelationRulesFalseMatchIsolation(t *testing.T) {
	engine := NewDefaultCorrelationRuleEngine()
	tenantA := uuid.New()
	tenantB := uuid.New()

	finding1 := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantA,
		Title:            "Open Port 22 SSH",
		AffectedEndpoint: "https://host1.example.com",
		Severity:         "HIGH",
	}

	finding2 := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantA,
		Title:            "Cross-Site Scripting",
		AffectedEndpoint: "https://host2.example.com/contact",
		Severity:         "HIGH", // Same severity, but completely unrelated
	}

	// 1. Same severity on unrelated issues -> no match
	if match := engine.EvaluatePair(finding1, finding2); match != nil {
		t.Errorf("expected no match between unrelated findings sharing only severity, got %v", match)
	}

	// 2. Cross-tenant isolation -> no match (must return nil)
	findingCrossTenant := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantB,
		Title:            "Apache Log4j RCE",
		AffectedEndpoint: "https://host1.example.com/login",
		CVEIDs:           []string{"CVE-2021-44228"},
	}

	findingSameTenant := &PersistentFinding{
		ID:               uuid.New(),
		TenantID:         tenantA,
		Title:            "Apache Log4j RCE",
		AffectedEndpoint: "https://host1.example.com/login",
		CVEIDs:           []string{"CVE-2021-44228"},
	}

	if match := engine.EvaluatePair(findingSameTenant, findingCrossTenant); match != nil {
		t.Errorf("expected nil on cross-tenant findings pair, got %v", match)
	}
}
