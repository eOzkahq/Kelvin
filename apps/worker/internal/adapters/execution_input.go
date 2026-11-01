package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/limits"
	"github.com/kelvin/kelvin/packages/common/scope"
)

const ExecutionInputVersion = "1.0"

// ExecutionInput is the versioned, least-privilege payload delivered to one
// scanner invocation. It must be built from validated worker context, never
// decoded directly from a user or queue payload.
type ExecutionInput struct {
	SchemaVersion string            `json:"schema_version"`
	Assessment    AssessmentContext `json:"assessment"`
	Target        TargetContext     `json:"target"`
	Scope         ScopeContext      `json:"scope"`
	Profile       ProfileContext    `json:"profile"`
	Scanner       ScannerContext    `json:"scanner"`
	Execution     ExecutionPolicy   `json:"execution"`
	Trace         TraceContext      `json:"trace"`
}

type AssessmentContext struct {
	ID              string `json:"id"`
	TenantID        string `json:"tenant_id"`
	AuthorizationID string `json:"authorization_id,omitempty"`
}

type TargetContext struct {
	Canonical string   `json:"canonical"`
	PinnedIPs []string `json:"pinned_ips"`
}

// ScopeContext carries a reference to the approved scope and the exact target
// authorized for this invocation. It intentionally omits the full project
// allow-list so scanners cannot discover sibling assets.
type ScopeContext struct {
	ID     string `json:"id"`
	Target string `json:"target"`
}

type ProfileContext struct {
	ID string `json:"id"`
}

type ScannerContext struct {
	Name          string          `json:"name"`
	ConfigVersion string          `json:"config_version"`
	Config        json.RawMessage `json:"config,omitempty"`
}

type ExecutionPolicy struct {
	ResourcePolicyID     string    `json:"resource_policy_id"`
	Deadline             time.Time `json:"deadline"`
	TimeoutSeconds       int64     `json:"timeout_seconds"`
	RequestsPerSecond    int       `json:"requests_per_second"`
	MaxRequestsPerTarget int       `json:"max_requests_per_target"`
	MaxConcurrentConns   int       `json:"max_concurrent_connections"`
	CPUQuota             string    `json:"cpu_quota"`
	MemoryLimit          string    `json:"memory_limit"`
	DiskLimit            string    `json:"disk_limit"`
	MaxPIDs              int64     `json:"max_pids"`
}

type TraceContext struct {
	JobID         string `json:"job_id"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// DecodeExecutionInput decodes one versioned wire payload, rejects unknown or
// trailing fields, and validates the resulting contract value.
func DecodeExecutionInput(raw []byte) (ExecutionInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input ExecutionInput
	if err := decoder.Decode(&input); err != nil {
		return ExecutionInput{}, fmt.Errorf("adapters: decode execution input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ExecutionInput{}, fmt.Errorf("adapters: execution input contains trailing JSON")
		}
		return ExecutionInput{}, fmt.Errorf("adapters: invalid trailing data in execution input: %w", err)
	}
	if err := input.Validate(); err != nil {
		return ExecutionInput{}, err
	}
	return input, nil
}

// InvocationAuthorization contains identifiers established by the trusted
// assessment/authorization service. These identifiers and the scope policy
// must come from trusted worker context, not scanner config or user input.
type InvocationAuthorization struct {
	ScopeID         string
	AuthorizationID string
}

// BuildExecutionInput resolves and validates the task target against the
// approved policy, captures the checked addresses, and copies only bounded
// invocation data. Scanner config is data, never CLI syntax or environment.
func BuildExecutionInput(ctx context.Context, task Task, auth InvocationAuthorization, policy scope.Policy, resourcePolicyID string, resource limits.Limits, profile ProfileBudget, now time.Time) (ExecutionInput, error) {
	if err := ValidateTask(task); err != nil {
		return ExecutionInput{}, err
	}
	if _, err := uuid.Parse(auth.ScopeID); err != nil {
		return ExecutionInput{}, fmt.Errorf("adapters: invalid authorized scope id: %w", err)
	}
	if auth.AuthorizationID != "" {
		if _, err := uuid.Parse(auth.AuthorizationID); err != nil {
			return ExecutionInput{}, fmt.Errorf("adapters: invalid authorization id: %w", err)
		}
	}
	if resourcePolicyID == "" {
		return ExecutionInput{}, fmt.Errorf("adapters: resource policy id is required")
	}
	if err := resource.Validate(); err != nil {
		return ExecutionInput{}, fmt.Errorf("adapters: invalid resource policy: %w", err)
	}
	if task.HardDeadline > resource.HardDeadline {
		return ExecutionInput{}, fmt.Errorf("adapters: task deadline exceeds resource policy")
	}
	if err := validateProfileBudget(profile); err != nil {
		return ExecutionInput{}, err
	}
	if now.IsZero() {
		return ExecutionInput{}, fmt.Errorf("adapters: invocation time is required")
	}
	canonical, pinned, err := policy.Validate(ctx, task.Target)
	if err != nil {
		return ExecutionInput{}, fmt.Errorf("adapters: target scope validation failed: %w", err)
	}
	if len(pinned) == 0 {
		return ExecutionInput{}, fmt.Errorf("adapters: target validation produced no pinned addresses")
	}
	ips := make([]string, 0, len(pinned))
	for _, ip := range pinned {
		ip = ip.Unmap()
		if !ip.IsValid() || scope.IsProhibited(ip) {
			return ExecutionInput{}, fmt.Errorf("adapters: target contains prohibited pinned address")
		}
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)
	configInput := append(json.RawMessage(nil), task.Payload...)
	if len(configInput) == 0 {
		defaults, err := DefaultScannerConfig(task.Scanner)
		if err != nil {
			return ExecutionInput{}, err
		}
		configInput, err = json.Marshal(defaults)
		if err != nil {
			return ExecutionInput{}, fmt.Errorf("adapters: encode default scanner config: %w", err)
		}
	}
	config, err := DecodeScannerConfig(configInput)
	if err != nil {
		return ExecutionInput{}, err
	}
	if config.ScannerID != task.Scanner {
		return ExecutionInput{}, fmt.Errorf("adapters: scanner config id does not match task scanner")
	}
	if task.HardDeadline < profile.MaxDuration {
		profile.MaxDuration = task.HardDeadline
	}
	if err := config.ValidateWithinProfile(profile); err != nil {
		return ExecutionInput{}, err
	}
	if profile.MaxRequestsPerTarget > resource.MaxRequestsPerTarget {
		return ExecutionInput{}, fmt.Errorf("adapters: product request budget exceeds worker resource limit")
	}
	effectiveTimeout := time.Duration(config.MaxDurationSeconds) * time.Second
	if task.HardDeadline < effectiveTimeout {
		effectiveTimeout = task.HardDeadline
	}
	if resource.HardDeadline < effectiveTimeout {
		effectiveTimeout = resource.HardDeadline
	}
	effectiveConcurrency := config.MaxConcurrency
	if profile.MaxConcurrency < effectiveConcurrency {
		effectiveConcurrency = profile.MaxConcurrency
	}
	if resource.MaxConcurrentConns < effectiveConcurrency {
		effectiveConcurrency = resource.MaxConcurrentConns
	}
	effectiveRate := config.RequestsPerSecond
	if profile.RequestsPerSecond < effectiveRate {
		effectiveRate = profile.RequestsPerSecond
	}
	config.MaxDurationSeconds = int(effectiveTimeout / time.Second)
	config.MaxConcurrency = effectiveConcurrency
	config.RequestsPerSecond = effectiveRate
	if err := config.Validate(); err != nil {
		return ExecutionInput{}, err
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return ExecutionInput{}, fmt.Errorf("adapters: encode scanner config: %w", err)
	}
	if err := validateScannerConfig(configBytes); err != nil {
		return ExecutionInput{}, err
	}
	deadline := now.Add(effectiveTimeout).UTC()
	input := ExecutionInput{
		SchemaVersion: ExecutionInputVersion,
		Assessment:    AssessmentContext{ID: task.AssessmentID, TenantID: task.TenantID, AuthorizationID: auth.AuthorizationID},
		Target:        TargetContext{Canonical: canonical.Canonical, PinnedIPs: ips},
		Scope:         ScopeContext{ID: auth.ScopeID, Target: canonical.Canonical},
		Profile:       ProfileContext{ID: task.ProfileID},
		Scanner:       ScannerContext{Name: task.Scanner, ConfigVersion: config.SchemaVersion, Config: configBytes},
		Execution: ExecutionPolicy{
			ResourcePolicyID: resourcePolicyID, Deadline: deadline, TimeoutSeconds: int64(effectiveTimeout.Seconds()),
			RequestsPerSecond: effectiveRate, MaxRequestsPerTarget: profile.MaxRequestsPerTarget,
			MaxConcurrentConns: effectiveConcurrency, CPUQuota: resource.CPUQuota,
			MemoryLimit: resource.MemoryLimit, DiskLimit: resource.DiskLimit, MaxPIDs: resource.MaxPIDs,
		},
		Trace: TraceContext{JobID: task.JobID, CorrelationID: task.CorrelationID},
	}
	if err := input.Validate(); err != nil {
		return ExecutionInput{}, err
	}
	return input, nil
}

// Validate rejects incomplete or internally inconsistent invocation data.
// It does not establish authorization; only BuildExecutionInput can bind the
// target to a validated Phase 1 scope policy.
func (in ExecutionInput) Validate() error {
	if in.SchemaVersion != ExecutionInputVersion {
		return fmt.Errorf("adapters: unsupported execution input schema version %q", in.SchemaVersion)
	}
	if _, err := uuid.Parse(in.Assessment.ID); err != nil {
		return fmt.Errorf("adapters: invalid assessment id")
	}
	if _, err := uuid.Parse(in.Assessment.TenantID); err != nil {
		return fmt.Errorf("adapters: invalid tenant id")
	}
	if in.Assessment.AuthorizationID != "" {
		if _, err := uuid.Parse(in.Assessment.AuthorizationID); err != nil {
			return fmt.Errorf("adapters: invalid authorization id")
		}
	}
	if _, err := uuid.Parse(in.Trace.JobID); err != nil {
		return fmt.Errorf("adapters: invalid job id")
	}
	if _, err := uuid.Parse(in.Scope.ID); err != nil {
		return fmt.Errorf("adapters: invalid scope id")
	}
	if in.Target.Canonical == "" || in.Target.Canonical != in.Scope.Target {
		return fmt.Errorf("adapters: target must match exact authorized scope target")
	}
	u, err := url.Parse(in.Target.Canonical)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("adapters: target must be a canonical HTTP(S) URL")
	}
	if len(in.Target.PinnedIPs) == 0 {
		return fmt.Errorf("adapters: at least one pinned target IP is required")
	}
	for _, rawIP := range in.Target.PinnedIPs {
		ip, err := netip.ParseAddr(rawIP)
		if err != nil || ip.String() != rawIP || scope.IsProhibited(ip) {
			return fmt.Errorf("adapters: invalid or prohibited pinned target IP")
		}
	}
	if in.Profile.ID == "" || in.Scanner.Name == "" || in.Execution.ResourcePolicyID == "" {
		return fmt.Errorf("adapters: profile, scanner, and resource policy are required")
	}
	if in.Scanner.ConfigVersion != ScannerConfigVersion {
		return fmt.Errorf("adapters: unsupported scanner config version %q", in.Scanner.ConfigVersion)
	}
	config, err := DecodeScannerConfig(in.Scanner.Config)
	if err != nil {
		return err
	}
	if config.ScannerID != in.Scanner.Name {
		return fmt.Errorf("adapters: scanner config id does not match invocation scanner")
	}
	if int64(config.MaxDurationSeconds) != in.Execution.TimeoutSeconds || config.RequestsPerSecond != in.Execution.RequestsPerSecond || config.MaxConcurrency != in.Execution.MaxConcurrentConns {
		return fmt.Errorf("adapters: effective scanner settings must match enforced invocation budgets")
	}
	if in.Execution.Deadline.IsZero() || in.Execution.TimeoutSeconds <= 0 || in.Execution.RequestsPerSecond <= 0 || in.Execution.RequestsPerSecond > 1000 || in.Execution.MaxRequestsPerTarget <= 0 || in.Execution.MaxConcurrentConns <= 0 || in.Execution.CPUQuota == "" || in.Execution.MemoryLimit == "" || in.Execution.DiskLimit == "" || in.Execution.MaxPIDs <= 0 {
		return fmt.Errorf("adapters: incomplete execution resource policy")
	}
	resource := limits.Limits{
		CPUQuota: in.Execution.CPUQuota, MemoryLimit: in.Execution.MemoryLimit,
		DiskLimit: in.Execution.DiskLimit, MaxPIDs: in.Execution.MaxPIDs,
		MaxConcurrentConns:   in.Execution.MaxConcurrentConns,
		MaxRequestsPerTarget: in.Execution.MaxRequestsPerTarget,
		// Scanner-local timeouts may be shorter than the minimum worker job
		// deadline accepted by limits.Validate; the profile check below binds it.
		HardDeadline: limits.MinHardDeadline,
	}
	if err := resource.Validate(); err != nil {
		return fmt.Errorf("adapters: invalid execution resource policy: %w", err)
	}
	if err := config.ValidateWithinProfile(ProfileBudget{
		RequestsPerSecond: in.Execution.RequestsPerSecond, MaxConcurrency: in.Execution.MaxConcurrentConns,
		MaxRequestsPerTarget: in.Execution.MaxRequestsPerTarget,
		MaxDuration:          time.Duration(in.Execution.TimeoutSeconds) * time.Second,
	}); err != nil {
		return err
	}
	return nil
}

// validateScannerConfig prevents scanner configuration from becoming an
// alternative command line, environment, target, or credential channel.
func validateScannerConfig(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("adapters: scanner config must be valid JSON: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("adapters: scanner config must be a JSON object")
	}
	return validateConfigValue(object, "")
}

func validateConfigValue(value any, parent string) error {
	prohibited := map[string]bool{
		"args": true, "argv": true, "command": true, "target": true, "url": true,
		"env": true, "envvars": true, "environment": true, "template": true,
		"templates": true, "templatepath": true, "templatespath": true,
		"workflow": true, "workflows": true, "password": true, "token": true,
		"apikey": true, "authorization": true, "cookie": true, "cookies": true,
		"secret": true, "credential": true, "credentials": true,
	}
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
			if prohibited[normalized] {
				return fmt.Errorf("adapters: scanner config field %q is prohibited", key)
			}
			if strings.HasSuffix(normalized, "ref") && (strings.Contains(normalized, "secret") || strings.Contains(normalized, "credential") || strings.Contains(normalized, "token")) {
				reference, ok := child.(string)
				if !ok || !(strings.HasPrefix(reference, "secret://") || strings.HasPrefix(reference, "vault://")) {
					return fmt.Errorf("adapters: %q must contain an opaque secret:// or vault:// reference", key)
				}
				continue // secret values are resolved separately and never enter this payload
			}
			if err := validateConfigValue(child, parent+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := validateConfigValue(child, parent); err != nil {
				return err
			}
		}
	}
	return nil
}
