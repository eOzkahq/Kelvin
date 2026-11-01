package adapters

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

// ScopePolicyProvider returns the trusted Phase 1 policy for this exact task.
// It must source tenant authorization from worker context, never scanner input.
type ScopePolicyProvider func(context.Context, Task) (scope.Policy, error)

// HTTPPreflightAdapter performs one bounded HEAD request against the validated
// target. A redirect can only be followed when the Phase 1 policy approves it.
// It never crawls and has no persistence or external-process dependency.
type HTTPPreflightAdapter struct {
	*ReferenceAdapter
	policyForTask ScopePolicyProvider
	rateMu        sync.Mutex
	nextRequest   time.Time
}

func NewHTTPPreflightAdapter(policyForTask ScopePolicyProvider) *HTTPPreflightAdapter {
	adapter := &HTTPPreflightAdapter{
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerHTTPPreflight,
			Caps: Capabilities{
				CheckCategories:      []string{"http_reachability", "http_response"},
				SupportedTargetTypes: []string{"url"}, SupportedProtocols: []string{"http", "https"},
				PassiveOnly: true, RequiresNetwork: true, SupportsCancel: true,
				MaxConcurrency: 1, MaxRequestRate: 2, MaxRequests: 1,
			},
		},
		policyForTask: policyForTask,
	}
	adapter.Run = adapter.run
	return adapter
}

func (a *HTTPPreflightAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a.policyForTask == nil {
		return fmt.Errorf("adapters: HTTP preflight requires a trusted scope policy provider")
	}
	return a.ReferenceAdapter.Initialize(ctx, logger)
}

func (a *HTTPPreflightAdapter) ValidateConfig(raw json.RawMessage) error {
	config, err := preflightConfig(Task{Scanner: ScannerHTTPPreflight, Payload: raw})
	if err != nil {
		return err
	}
	if config.RequestsPerSecond > a.Capabilities().MaxRequestRate || config.MaxConcurrency > a.Capabilities().MaxConcurrency {
		return fmt.Errorf("adapters: HTTP preflight config exceeds adapter request or concurrency limits")
	}
	return nil
}

func (a *HTTPPreflightAdapter) run(ctx context.Context, task Task) (Result, error) {
	config, err := preflightConfig(task)
	if err != nil {
		return Result{}, err
	}
	if err := a.ValidateConfig(task.Payload); err != nil {
		return Result{}, err
	}
	started := time.Now().UTC()
	deadline := time.Duration(config.MaxDurationSeconds) * time.Second
	if task.HardDeadline < deadline {
		deadline = task.HardDeadline
	}
	operationCtx, operationCancel := context.WithTimeout(ctx, deadline)
	defer operationCancel()
	policy, err := a.policyForTask(operationCtx, task)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: load authorized target scope: %w", err)
	}
	target, _, err := policy.Validate(operationCtx, task.Target)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: HTTP preflight target rejected by scope policy: %w", err)
	}
	approvedURL, err := url.Parse(target.Canonical)
	if err != nil || approvedURL == nil || (approvedURL.Scheme != "http" && approvedURL.Scheme != "https") {
		return Result{}, fmt.Errorf("adapters: HTTP preflight requires an approved HTTP or HTTPS URL")
	}

	requestTimeout := time.Duration(config.RequestTimeoutSeconds) * time.Second
	if deadline < requestTimeout {
		requestTimeout = deadline
	}
	client := policy.NewHTTPClient()
	client.Timeout = requestTimeout

	if err := a.waitForRequestSlot(operationCtx, config.RequestsPerSecond); err != nil {
		return Result{}, err
	}
	requestCtx, requestCancel := context.WithTimeout(operationCtx, requestTimeout)
	defer requestCancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodHead, approvedURL.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: build HTTP preflight request: %w", err)
	}
	request.Header.Set("User-Agent", "Kelvin-Preflight/1.0")
	request.Header.Set("Accept", "*/*")

	requestStarted := time.Now()
	response, requestErr := client.Do(request)
	latency := time.Since(requestStarted)
	completed := time.Now().UTC()
	observation := preflightObservation{
		Outcome: "UNREACHABLE", Target: target.Canonical, LatencyMS: latency.Milliseconds(),
	}
	diagnostics := []ExecutionDiagnostic{}
	status := StatusCompleted
	var exitCode *int
	zero := 0
	if requestErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if response != nil {
			observation.StatusCode = response.StatusCode
			observation.Protocol = response.Proto
			observation.Redirected = response.StatusCode >= 300 && response.StatusCode < 400 && response.Header.Get("Location") != ""
		}
		observation.Error = classifyPreflightError(requestCtx, requestErr)
		switch {
		case errors.Is(requestCtx.Err(), context.Canceled):
			status = StatusCancelled
			diagnostics = []ExecutionDiagnostic{{Level: "error", Code: "CANCELLED", Message: "HTTP preflight request was cancelled"}}
		case errors.Is(requestCtx.Err(), context.DeadlineExceeded):
			status = StatusTimedOut
			diagnostics = []ExecutionDiagnostic{{Level: "error", Code: "DEADLINE_EXCEEDED", Message: "HTTP preflight request exceeded its configured timeout"}}
		default:
			status = StatusCompletedWithWarnings
			exitCode = &zero
			diagnostics = []ExecutionDiagnostic{{Level: "warning", Code: "TARGET_UNREACHABLE", Message: "HTTP preflight could not obtain a response"}}
		}
	} else {
		defer response.Body.Close()
		observation.Outcome = "HTTP_RESPONDED"
		observation.StatusCode = response.StatusCode
		observation.Protocol = response.Proto
		observation.Redirected = response.Request != nil && response.Request.URL.String() != target.Canonical
		if response.Request != nil {
			observation.FinalURL = response.Request.URL.String()
		}
		if response.TLS != nil {
			observation.TLSVersion = tls.VersionName(response.TLS.Version)
			observation.TLSCipherSuite = tls.CipherSuiteName(response.TLS.CipherSuite)
		}
		exitCode = &zero
	}
	metadata, err := json.Marshal(observation)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: encode HTTP preflight observation: %w", err)
	}
	return Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID: task.AssessmentID, ScannerID: ScannerHTTPPreflight,
			ScannerVersion: a.Version(), AdapterVersion: a.Version(), RunID: uuid.NewString(),
			StartedAt: started, CompletedAt: completed, CorrelationID: task.CorrelationID,
		},
		Status: status, ExitCode: exitCode, DurationMS: time.Since(started).Milliseconds(),
		Findings: []json.RawMessage{}, Diagnostics: diagnostics,
		ScannerMetadata: map[string]json.RawMessage{"http_preflight.observation": metadata},
		RawArtifacts:    RawArtifactReferences{},
	}, nil
}

func (a *HTTPPreflightAdapter) waitForRequestSlot(ctx context.Context, requestsPerSecond int) error {
	interval := time.Second / time.Duration(requestsPerSecond)
	a.rateMu.Lock()
	now := time.Now()
	wait := a.nextRequest.Sub(now)
	if wait <= 0 {
		a.nextRequest = now.Add(interval)
		a.rateMu.Unlock()
		return nil
	}
	a.nextRequest = a.nextRequest.Add(interval)
	a.rateMu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type preflightObservation struct {
	Outcome        string `json:"outcome"`
	Target         string `json:"target"`
	FinalURL       string `json:"final_url,omitempty"`
	StatusCode     int    `json:"status_code,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	TLSCipherSuite string `json:"tls_cipher_suite,omitempty"`
	LatencyMS      int64  `json:"latency_ms"`
	Redirected     bool   `json:"redirected"`
	Error          string `json:"error,omitempty"`
}

func preflightConfig(task Task) (ScannerConfigV1, error) {
	raw := task.Payload
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		defaults, err := DefaultScannerConfig(ScannerHTTPPreflight)
		if err != nil {
			return ScannerConfigV1{}, err
		}
		return defaults, nil
	}
	config, err := DecodeScannerConfig(raw)
	if err != nil {
		return ScannerConfigV1{}, err
	}
	if config.ScannerID != ScannerHTTPPreflight {
		return ScannerConfigV1{}, fmt.Errorf("adapters: HTTP preflight received config for scanner %q", config.ScannerID)
	}
	return config, nil
}

func classifyPreflightError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, scope.ErrOutOfScope) || errors.Is(err, scope.ErrProhibited) {
		return "redirect_rejected_by_scope"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && strings.Contains(strings.ToLower(urlErr.Err.Error()), "tls") {
		return "tls_error"
	}
	return "connection_error"
}

var _ ScannerAdapter = (*HTTPPreflightAdapter)(nil)
