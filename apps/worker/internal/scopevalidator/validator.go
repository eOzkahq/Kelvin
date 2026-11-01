// Package scopevalidator enforces assessment target scope on scanner-reported
// findings, quarantining and rejecting any finding that references out-of-scope
// or prohibited targets.
package scopevalidator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

var (
	ErrScopeViolation = errors.New("scopevalidator: target reference is outside approved assessment scope")
)

// ScopeViolation details an out-of-scope or prohibited target reference rejected from findings.
type ScopeViolation struct {
	FindingTitle string    `json:"finding_title"`
	TargetRef    string    `json:"target_ref"`
	Reason       string    `json:"reason"`
	DetectedAt   time.Time `json:"detected_at"`
}

// Validator validates finding targets against the assessment scope policy.
type Validator struct {
	policy scope.Policy
	logger *zap.Logger
}

// New creates a finding scope validator using the provided scope policy.
func New(policy scope.Policy, logger *zap.Logger) *Validator {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Validator{
		policy: policy,
		logger: logger,
	}
}

// NewFromTarget constructs a scope validator based on a primary target URL or domain.
func NewFromTarget(rawTarget string, logger *zap.Logger) (*Validator, error) {
	norm, err := scope.Normalize(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("scopevalidator: invalid base target: %w", err)
	}

	var domains []string
	var cidrs []string

	if norm.Host != "" {
		domains = append(domains, norm.Host)
	}
	if norm.Prefix.IsValid() {
		cidrs = append(cidrs, norm.Prefix.String())
	}
	if norm.IP.IsValid() {
		cidrs = append(cidrs, netip.PrefixFrom(norm.IP, norm.IP.BitLen()).String())
	}

	policy, err := scope.NewPolicy(domains, cidrs, staticResolver{host: norm.Host, ip: norm.IP})
	if err != nil {
		return nil, fmt.Errorf("scopevalidator: create policy: %w", err)
	}

	return New(policy, logger), nil
}

// ValidateTargetRef validates a single target reference (URL, hostname, or IP).
func (v *Validator) ValidateTargetRef(ctx context.Context, targetRef string) error {
	trimmed := strings.TrimSpace(targetRef)
	if trimmed == "" {
		return errors.New("scopevalidator: empty target reference")
	}

	// Extract hostname if targetRef is a full URL
	targetCandidate := trimmed
	if strings.Contains(targetCandidate, "://") {
		u, err := url.Parse(targetCandidate)
		if err == nil && u.Hostname() != "" {
			targetCandidate = u.Hostname()
		}
	}

	// First verify host allowance
	if !v.policy.HostAllowed(targetCandidate) {
		return fmt.Errorf("%w: host %q is not in allowed domains or CIDRs", ErrScopeViolation, targetCandidate)
	}

	// Validate against full scope rules (anti-SSRF, loopback, private IP checks)
	_, _, err := v.policy.Validate(ctx, targetCandidate)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrScopeViolation, err.Error())
	}

	return nil
}

// FilterFindings inspects scanner findings, stripping any finding referencing an out-of-scope target.
func (v *Validator) FilterFindings(ctx context.Context, findings []json.RawMessage) ([]json.RawMessage, []ScopeViolation, error) {
	accepted := make([]json.RawMessage, 0, len(findings))
	violations := make([]ScopeViolation, 0)

	for i, raw := range findings {
		var f map[string]any
		if err := json.Unmarshal(raw, &f); err != nil {
			v.logger.Warn("dropping unparseable finding during scope validation",
				zap.Int("finding_index", i),
				zap.Error(err),
			)
			continue
		}

		title, _ := f["title"].(string)
		if title == "" {
			title = fmt.Sprintf("finding-%d", i)
		}

		// Extract target references
		targetMap, _ := f["target"].(map[string]any)
		var refs []string
		if targetMap != nil {
			if asset, ok := targetMap["asset"].(string); ok && asset != "" {
				refs = append(refs, asset)
			}
			if u, ok := targetMap["url"].(string); ok && u != "" {
				refs = append(refs, u)
			}
			if host, ok := targetMap["host"].(string); ok && host != "" {
				refs = append(refs, host)
			}
		}

		// If no target was specified, reject finding
		if len(refs) == 0 {
			v.logger.Warn("dropping finding with missing target reference",
				zap.String("finding_title", title),
			)
			violations = append(violations, ScopeViolation{
				FindingTitle: title,
				TargetRef:    "",
				Reason:       "missing target reference in finding",
				DetectedAt:   time.Now().UTC(),
			})
			continue
		}

		// Validate all extracted target references
		violationFound := false
		for _, ref := range refs {
			if err := v.ValidateTargetRef(ctx, ref); err != nil {
				v.logger.Warn("quarantined out-of-scope finding target",
					zap.String("finding_title", title),
					zap.String("target_ref", ref),
					zap.Error(err),
				)
				violations = append(violations, ScopeViolation{
					FindingTitle: title,
					TargetRef:    ref,
					Reason:       err.Error(),
					DetectedAt:   time.Now().UTC(),
				})
				violationFound = true
				break
			}
		}

		if !violationFound {
			accepted = append(accepted, raw)
		}
	}

	return accepted, violations, nil
}

// ToDiagnostics converts scope violations into canonical execution diagnostics.
func ToDiagnostics(violations []ScopeViolation) []adapters.ExecutionDiagnostic {
	if len(violations) == 0 {
		return nil
	}
	diags := make([]adapters.ExecutionDiagnostic, 0, len(violations))
	for _, v := range violations {
		diags = append(diags, adapters.ExecutionDiagnostic{
			Level:   "info",
			Code:    "OUT_OF_SCOPE_TARGET_REJECTED",
			Message: fmt.Sprintf("rejected finding %q: target reference %q is out of assessment scope (%s)", v.FindingTitle, v.TargetRef, v.Reason),
		})
	}
	return diags
}

type staticResolver struct {
	host string
	ip   netip.Addr
}

func (r staticResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.ip.IsValid() {
		return []netip.Addr{r.ip}, nil
	}
	// Return public IP mock for test hostnames
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}
