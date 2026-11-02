package integrations

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrProviderUnavailable = errors.New("integrations: external provider service unavailable")
	ErrProviderRateLimited = errors.New("integrations: external provider rate limit reached (HTTP 429)")
	ErrProviderAuthFailed  = errors.New("integrations: external provider authentication failed (HTTP 401/403)")
	ErrInvalidPayload      = errors.New("integrations: invalid payload format for action")
	ErrAdapterNotFound     = errors.New("integrations: adapter not registered for provider")
	ErrDuplicateAdapter    = errors.New("integrations: adapter already registered for provider")
)

type AdapterCapability string

const (
	CapabilityTicketSync        AdapterCapability = "TICKET_SYNC"
	CapabilityAlertNotification AdapterCapability = "ALERT_NOTIFICATION"
	CapabilityAuditStream       AdapterCapability = "AUDIT_STREAM"
	CapabilityUserProvisioning  AdapterCapability = "USER_PROVISIONING"
)

type HealthState string

const (
	HealthHealthy     HealthState = "HEALTHY"
	HealthDegraded    HealthState = "DEGRADED"
	HealthUnreachable HealthState = "UNREACHABLE"
)

// HealthStatus documents provider reachability and latency.
type HealthStatus struct {
	State     HealthState `json:"state"`
	LatencyMs int64       `json:"latency_ms"`
	Message   string      `json:"message"`
	CheckedAt time.Time   `json:"checked_at"`
}

// ExecutionContext supplies complete execution parameters strictly isolated to tenant boundaries.
type ExecutionContext struct {
	OrganizationID  uuid.UUID      `json:"organization_id"`
	WorkspaceID     *uuid.UUID     `json:"workspace_id,omitempty"`
	ConnectionID    uuid.UUID      `json:"connection_id"`
	Provider        ProviderType   `json:"provider"`
	Action          string         `json:"action"`
	Payload         map[string]any `json:"payload"`
	DecryptedSecret string         `json:"-"` // Ephemeral in memory
	EndpointURL     string         `json:"endpoint_url"`
	Config          map[string]any `json:"config"`
}

// ExecutionResult records the outcome of an external operation.
type ExecutionResult struct {
	Success      bool           `json:"success"`
	ExternalID   string         `json:"external_id,omitempty"`
	ExternalURL  string         `json:"external_url,omitempty"`
	ResponseData map[string]any `json:"response_data,omitempty"`
	DurationMs   int64          `json:"duration_ms"`
	ExecutedAt   time.Time      `json:"executed_at"`
}

// IntegrationAdapter defines the standardized interface contract for all external tool integrations.
type IntegrationAdapter interface {
	Provider() ProviderType
	Version() string
	Capabilities() []AdapterCapability
	ValidateConfig(ctx context.Context, config map[string]any) error
	CheckHealth(ctx context.Context, conn *IntegrationConnection, decryptedSecret string) (*HealthStatus, error)
	Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error)
}

// AdapterRegistry maintains registered integration adapters with thread safety.
type AdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[ProviderType]IntegrationAdapter
}

func NewAdapterRegistry() *AdapterRegistry {
	return &AdapterRegistry{
		adapters: make(map[ProviderType]IntegrationAdapter),
	}
}

// Register registers an adapter implementation.
func (r *AdapterRegistry) Register(adapter IntegrationAdapter) error {
	if adapter == nil {
		return errors.New("integrations: cannot register nil adapter")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	p := adapter.Provider()
	if _, exists := r.adapters[p]; exists {
		return fmt.Errorf("%w: '%s'", ErrDuplicateAdapter, p)
	}

	r.adapters[p] = adapter
	return nil
}

// Get resolves the adapter for a provider.
func (r *AdapterRegistry) Get(provider ProviderType) (IntegrationAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, exists := r.adapters[provider]
	if !exists {
		return nil, fmt.Errorf("%w: '%s'", ErrAdapterNotFound, provider)
	}
	return adapter, nil
}

// Execute safely dispatches work to the target adapter, recording timing and catching panics.
func (r *AdapterRegistry) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	adapter, err := r.Get(execCtx.Provider)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	res, err := adapter.Execute(ctx, execCtx)
	duration := time.Since(start).Milliseconds()

	if res != nil {
		res.DurationMs = duration
		res.ExecutedAt = time.Now().UTC()
	}

	return res, err
}

// ListRegisteredProviders returns all supported provider types.
func (r *AdapterRegistry) ListRegisteredProviders() []ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var providers []ProviderType
	for p := range r.adapters {
		providers = append(providers, p)
	}
	return providers
}
