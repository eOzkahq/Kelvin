// Package adapter defines the scanner invocation input contract.
//
// All scanner engines receive input exclusively through this validated, versioned
// structure. No arbitrary CLI flags or untrusted user input can bypass this boundary.
package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// InputSchemaVersion is the current version of the scanner invocation input contract.
const InputSchemaVersion = "1.0"

var (
	// Disallow dangerous shell characters in target inputs
	safeTargetRe = regexp.MustCompile(`^[a-zA-Z0-9\.\-\_\:\/]+$`)
	// Safe flag key characters (alphanumeric, dashes, underscores)
	safeFlagKeyRe = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
)

// Sentinel errors for input contract validation failures.
var (
	ErrInvalidSchemaVersion = errors.New("input: unsupported schema version")
	ErrInvalidUUID          = errors.New("input: invalid identifier format")
	ErrScopeViolation       = errors.New("input: target outside approved assessment scope")
	ErrUnsafeInput          = errors.New("input: unsafe characters or arguments detected")
	ErrMissingRequiredField = errors.New("input: missing required field")
)

// CanonicalTarget defines the validated target endpoints for scanner execution.
type CanonicalTarget struct {
	Raw       string `json:"raw"`
	Scheme    string `json:"scheme"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	BasePath  string `json:"base_path,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

// ApprovedScope defines the explicit boundary of allowed assessment targets.
type ApprovedScope struct {
	ScopeID           string   `json:"scope_id"`
	AllowedHosts      []string `json:"allowed_hosts"`
	AllowedIPRanges   []string `json:"allowed_ip_ranges,omitempty"`
	AllowedPorts      []int    `json:"allowed_ports,omitempty"`
	DisallowedPaths   []string `json:"disallowed_paths,omitempty"`
	MaxRedirectDepth  int      `json:"max_redirect_depth"`
}

// ProfileContext details the scan profile constraints governing execution.
type ProfileContext struct {
	ProfileID         string        `json:"profile_id"`
	Name              string        `json:"name"`
	MaxRequestRate    int           `json:"max_request_rate"`
	MaxTargetRequests int           `json:"max_target_requests"`
	TimeoutPerRequest time.Duration `json:"timeout_per_request"`
	HardDeadline      time.Duration `json:"hard_deadline"`
	AllowedEngines    []string      `json:"allowed_engines"`
}

// ResourcePolicyRef defines the sandbox resource bounds applied under ADR-0005.
type ResourcePolicyRef struct {
	PolicyID       string  `json:"policy_id"`
	MaxMemoryBytes int64   `json:"max_memory_bytes"`
	CPUCores       float64 `json:"cpu_cores"`
	PIDsLimit      int64   `json:"pids_limit"`
	ReadOnlyRootFS bool    `json:"read_only_rootfs"`
}

// ScannerConfig encapsulates vetted engine-specific execution parameters.
type ScannerConfig struct {
	Engine             string            `json:"engine"`
	CuratedTemplateIDs []string          `json:"curated_template_ids,omitempty"`
	SafeFlags          map[string]string `json:"safe_flags,omitempty"`
	PassiveOnly        bool              `json:"passive_only"`
}

// InvocationInput is the root versioned contract passed to all KELVIN scanner adapters.
type InvocationInput struct {
	SchemaVersion     string            `json:"schema_version"`
	TaskID            string            `json:"task_id"`
	AssessmentID      string            `json:"assessment_id"`
	TenantID          string            `json:"tenant_id"`
	CorrelationID     string            `json:"correlation_id"`
	Target            CanonicalTarget   `json:"target"`
	Scope             ApprovedScope     `json:"scope"`
	Profile           ProfileContext    `json:"profile"`
	ResourcePolicy    ResourcePolicyRef `json:"resource_policy"`
	Scanner           ScannerConfig     `json:"scanner"`
	ExecutionDeadline time.Duration     `json:"execution_deadline"`
	CreatedAt         time.Time         `json:"created_at"`
}

// ValidateInvocationInput performs thorough validation of all fields against Phase 1 invariants.
func ValidateInvocationInput(in InvocationInput) error {
	if in.SchemaVersion != InputSchemaVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrInvalidSchemaVersion, in.SchemaVersion, InputSchemaVersion)
	}

	// UUID validations
	for name, id := range map[string]string{
		"task_id":       in.TaskID,
		"assessment_id": in.AssessmentID,
		"tenant_id":     in.TenantID,
	} {
		if id == "" {
			return fmt.Errorf("%w: %s is required", ErrMissingRequiredField, name)
		}
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("%w: %s (%q)", ErrInvalidUUID, name, id)
		}
	}

	// Target validations
	if in.Target.Host == "" && in.Target.Raw == "" {
		return fmt.Errorf("%w: target host or raw URL required", ErrMissingRequiredField)
	}
	targetStr := in.Target.Raw
	if targetStr == "" {
		targetStr = in.Target.Host
	}
	if !safeTargetRe.MatchString(targetStr) {
		return fmt.Errorf("%w: target contains invalid or shell-unsafe characters", ErrUnsafeInput)
	}

	// Parse host if not populated
	host := in.Target.Host
	if host == "" {
		if u, err := url.Parse(in.Target.Raw); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		} else {
			host = in.Target.Raw
		}
	}

	// Scope enforcement: target host must be in AllowedHosts if provided
	if len(in.Scope.AllowedHosts) > 0 {
		matched := false
		for _, allowed := range in.Scope.AllowedHosts {
			if strings.EqualFold(host, allowed) || (strings.HasPrefix(allowed, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(allowed[1:]))) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: host %q is not in allowed scope", ErrScopeViolation, host)
		}
	}

	// Port validation
	if in.Target.Port < 0 || in.Target.Port > 65535 {
		return fmt.Errorf("%w: port out of range", ErrUnsafeInput)
	}

	// Profile constraints
	if in.Profile.ProfileID == "" {
		return fmt.Errorf("%w: profile_id is required", ErrMissingRequiredField)
	}
	if in.Profile.HardDeadline <= 0 {
		return fmt.Errorf("%w: profile hard_deadline must be positive", ErrMissingRequiredField)
	}
	if in.ExecutionDeadline <= 0 {
		return fmt.Errorf("%w: execution_deadline must be positive", ErrMissingRequiredField)
	}

	// Scanner configuration validation
	if in.Scanner.Engine == "" {
		return fmt.Errorf("%w: scanner engine is required", ErrMissingRequiredField)
	}
	for k, v := range in.Scanner.SafeFlags {
		if !safeFlagKeyRe.MatchString(k) {
			return fmt.Errorf("%w: flag key %q contains invalid characters", ErrUnsafeInput, k)
		}
		// Block dangerous shell metacharacters in flag values
		if strings.ContainsAny(v, ";|&$`\n\r") {
			return fmt.Errorf("%w: flag value for %q contains forbidden metacharacters", ErrUnsafeInput, k)
		}
	}

	return nil
}

// ToExecutionInput maps an InvocationInput to the adapter.ExecutionInput struct.
func (in InvocationInput) ToExecutionInput() (ExecutionInput, error) {
	if err := ValidateInvocationInput(in); err != nil {
		return ExecutionInput{}, err
	}

	rawParams, err := json.Marshal(in.Scanner)
	if err != nil {
		return ExecutionInput{}, fmt.Errorf("failed to marshal scanner config: %w", err)
	}

	target := in.Target.Raw
	if target == "" {
		target = in.Target.Host
	}

	return ExecutionInput{
		TaskID:        in.TaskID,
		AssessmentID:  in.AssessmentID,
		TenantID:      in.TenantID,
		CorrelationID: in.CorrelationID,
		Target:        target,
		ProfileID:     in.Profile.ProfileID,
		Deadline:      in.ExecutionDeadline,
		Config: Config{
			MaxTimeout:   in.Profile.TimeoutPerRequest,
			MaxRateLimit: in.Profile.MaxRequestRate,
			CustomOptions: map[string]any{
				"engine": in.Scanner.Engine,
			},
		},
		Params: rawParams,
	}, nil
}
