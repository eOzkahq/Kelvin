package findings

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/kelvin/kelvin/packages/common/normalization"
)

// CorrelationMatchResult represents the outcome of evaluating a correlation rule between two findings.
type CorrelationMatchResult struct {
	Matched         bool            `json:"matched"`
	RuleID          string          `json:"rule_id"`
	RuleVersion     string          `json:"rule_version"`
	Confidence      float64         `json:"confidence"`
	CorrelationType CorrelationType `json:"correlation_type"`
	GroupName       string          `json:"group_name"`
	Rationale       string          `json:"rationale"`
	MatchedFactors  []string        `json:"matched_factors"`
}

// CorrelationRule defines the contract for evaluating cross-scanner finding correlation.
type CorrelationRule interface {
	ID() string
	Version() string
	Description() string
	Evaluate(a, b *PersistentFinding) *CorrelationMatchResult
}

// CorrelationRuleEngine orchestrates evaluation of versioned correlation rules across findings.
type CorrelationRuleEngine struct {
	rules []CorrelationRule
}

// NewDefaultCorrelationRuleEngine returns an engine initialized with default versioned rules.
func NewDefaultCorrelationRuleEngine() *CorrelationRuleEngine {
	return &CorrelationRuleEngine{
		rules: []CorrelationRule{
			&CommonCVERule{
				RuleVersion: "v1.0.0",
			},
			&SameEndpointCWERule{
				RuleVersion: "v1.0.0",
			},
			&HTTPHeaderBaselineRule{
				RuleVersion: "v1.0.0",
			},
		},
	}
}

// EvaluatePair evaluates finding pairs against all registered correlation rules, returning the highest-confidence match.
func (e *CorrelationRuleEngine) EvaluatePair(a, b *PersistentFinding) *CorrelationMatchResult {
	if a == nil || b == nil || a.ID == b.ID {
		return nil
	}
	if a.TenantID != b.TenantID {
		return nil // Multi-tenant isolation invariant
	}

	var bestMatch *CorrelationMatchResult
	for _, rule := range e.rules {
		match := rule.Evaluate(a, b)
		if match != nil && match.Matched {
			if bestMatch == nil || match.Confidence > bestMatch.Confidence {
				bestMatch = match
			}
		}
	}
	return bestMatch
}

// -----------------------------------------------------------------------------
// Rule 1: Common CVE Identifier Rule
// -----------------------------------------------------------------------------

// CommonCVERule correlates cross-scanner findings targeting the same asset with overlapping CVE identifiers.
type CommonCVERule struct {
	RuleVersion string
}

func (r *CommonCVERule) ID() string          { return "RULE_COMMON_CVE" }
func (r *CommonCVERule) Version() string     { return r.RuleVersion }
func (r *CommonCVERule) Description() string {
	return "Correlates findings targeting the same host asset with matching CVE identifiers"
}

func (r *CommonCVERule) Evaluate(a, b *PersistentFinding) *CorrelationMatchResult {
	assetA := extractHost(a.AffectedEndpoint)
	assetB := extractHost(b.AffectedEndpoint)
	if assetA == "" || assetB == "" || normalization.NormalizeAsset(assetA) != normalization.NormalizeAsset(assetB) {
		return nil
	}

	commonCVEs := intersectSlices(a.CVEIDs, b.CVEIDs)
	if len(commonCVEs) == 0 {
		return nil
	}

	return &CorrelationMatchResult{
		Matched:         true,
		RuleID:          r.ID(),
		RuleVersion:     r.Version(),
		Confidence:      0.95,
		CorrelationType: CorrelationCommonID,
		GroupName:       fmt.Sprintf("Common CVE Cluster: %s on %s", commonCVEs[0], assetA),
		Rationale:       fmt.Sprintf("Shared CVE identifier %v confirmed against target host %s", commonCVEs, assetA),
		MatchedFactors: []string{
			fmt.Sprintf("host:%s", assetA),
			fmt.Sprintf("cve:%s", strings.Join(commonCVEs, ",")),
		},
	}
}

// -----------------------------------------------------------------------------
// Rule 2: Same Endpoint CWE Taxonomy Rule
// -----------------------------------------------------------------------------

// SameEndpointCWERule correlates findings affecting the same HTTP endpoint sharing a Common Weakness Enumeration.
type SameEndpointCWERule struct {
	RuleVersion string
}

func (r *SameEndpointCWERule) ID() string          { return "RULE_SAME_ENDPOINT_CWE" }
func (r *SameEndpointCWERule) Version() string     { return r.RuleVersion }
func (r *SameEndpointCWERule) Description() string {
	return "Correlates findings affecting the identical endpoint with matching CWE weakness category"
}

func (r *SameEndpointCWERule) Evaluate(a, b *PersistentFinding) *CorrelationMatchResult {
	if a.CWEID == "" || b.CWEID == "" || a.CWEID != b.CWEID {
		return nil
	}
	if a.AffectedEndpoint == "" || b.AffectedEndpoint == "" {
		return nil
	}

	normEndpointA, errA := normalization.NormalizeEndpoint(a.AffectedEndpoint)
	normEndpointB, errB := normalization.NormalizeEndpoint(b.AffectedEndpoint)
	if errA != nil || errB != nil || normEndpointA != normEndpointB {
		return nil
	}

	return &CorrelationMatchResult{
		Matched:         true,
		RuleID:          r.ID(),
		RuleVersion:     r.Version(),
		Confidence:      0.85,
		CorrelationType: CorrelationSharedVulnClass,
		GroupName:       fmt.Sprintf("Shared Weakness %s on %s", a.CWEID, normEndpointA),
		Rationale:       fmt.Sprintf("Identical weakness taxonomy (%s) verified on shared endpoint %s", a.CWEID, normEndpointA),
		MatchedFactors: []string{
			fmt.Sprintf("endpoint:%s", normEndpointA),
			fmt.Sprintf("cwe:%s", a.CWEID),
		},
	}
}

// -----------------------------------------------------------------------------
// Rule 3: HTTP Security Header Baseline Rule
// -----------------------------------------------------------------------------

// HTTPHeaderBaselineRule correlates security header deficiencies on the same web asset.
type HTTPHeaderBaselineRule struct {
	RuleVersion string
}

func (r *HTTPHeaderBaselineRule) ID() string          { return "RULE_HTTP_HEADER_BASELINE" }
func (r *HTTPHeaderBaselineRule) Version() string     { return r.RuleVersion }
func (r *HTTPHeaderBaselineRule) Description() string {
	return "Correlates HTTP defense-in-depth and security header omissions on a shared web host"
}

func (r *HTTPHeaderBaselineRule) Evaluate(a, b *PersistentFinding) *CorrelationMatchResult {
	assetA := extractHost(a.AffectedEndpoint)
	assetB := extractHost(b.AffectedEndpoint)
	if assetA == "" || assetB == "" || normalization.NormalizeAsset(assetA) != normalization.NormalizeAsset(assetB) {
		return nil
	}

	if !isHeaderVulnerability(a) || !isHeaderVulnerability(b) {
		return nil
	}

	return &CorrelationMatchResult{
		Matched:         true,
		RuleID:          r.ID(),
		RuleVersion:     r.Version(),
		Confidence:      0.80,
		CorrelationType: CorrelationSharedVulnClass,
		GroupName:       fmt.Sprintf("HTTP Header Baseline Deficiencies on %s", assetA),
		Rationale:       fmt.Sprintf("Multiple defense-in-depth header omissions detected on host %s", assetA),
		MatchedFactors: []string{
			fmt.Sprintf("host:%s", assetA),
			"taxonomy:http_security_headers",
		},
	}
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

func extractHost(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return endpoint
}

func intersectSlices(a, b []string) []string {
	seen := make(map[string]bool)
	for _, v := range a {
		if v != "" {
			seen[strings.ToUpper(strings.TrimSpace(v))] = true
		}
	}
	var common []string
	for _, v := range b {
		upper := strings.ToUpper(strings.TrimSpace(v))
		if seen[upper] {
			common = append(common, upper)
			delete(seen, upper) // prevent duplicate additions
		}
	}
	return common
}

func isHeaderVulnerability(f *PersistentFinding) bool {
	if f == nil {
		return false
	}
	// Common header CWEs: CWE-693 (Protection Mechanism Failure), CWE-1021 (Anti-Clickjacking), CWE-319 (Cleartext Transmission), CWE-523
	if f.CWEID == "CWE-693" || f.CWEID == "CWE-1021" || f.CWEID == "CWE-319" || f.CWEID == "CWE-523" || f.CWEID == "CWE-942" {
		return true
	}
	lowerTitle := strings.ToLower(f.Title)
	if strings.Contains(lowerTitle, "hsts") ||
		strings.Contains(lowerTitle, "content-security-policy") ||
		strings.Contains(lowerTitle, "csp") ||
		strings.Contains(lowerTitle, "x-frame-options") ||
		strings.Contains(lowerTitle, "x-content-type-options") ||
		strings.Contains(lowerTitle, "referrer-policy") ||
		strings.Contains(lowerTitle, "strict-transport-security") {
		return true
	}
	return false
}
