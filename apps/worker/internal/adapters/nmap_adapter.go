package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// NmapReportRunner returns the raw XML output captured from a bounded Nmap container execution.
type NmapReportRunner func(context.Context, Task) ([]byte, error)

// NmapRuntimeVerifier measures and validates the container image and binary version identity.
type NmapRuntimeVerifier func(context.Context) (RuntimeVersionInfo, error)

type NmapAdapter struct {
	*ReferenceAdapter
	verify NmapRuntimeVerifier
	run    NmapReportRunner
}

func NewVerifiedNmapAdapter(verifier NmapRuntimeVerifier, runner NmapReportRunner) *NmapAdapter {
	a := &NmapAdapter{
		verify: verifier,
		run:    runner,
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerNmap,
			Caps: Capabilities{
				CheckCategories:      []string{"discovery", "port_scan", "service_detection"},
				SupportedTargetTypes: []string{"hostname", "ip", "url"},
				SupportedProtocols:   []string{"tcp", "http", "https"},
				PassiveOnly:          false,
				ActiveScanning:       true,
				RequiresNetwork:      true,
				RequiresSandbox:      true,
				SupportsCancel:       true,
				MaxConcurrency:       1,
				MaxRequestRate:       10,
				MaxRequests:          1000,
			},
		},
	}
	a.ReferenceAdapter.Run = a.executeReport
	return a
}

func (a *NmapAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a == nil || a.verify == nil || a.run == nil {
		return fmt.Errorf("adapters: Nmap adapter requires a runtime verifier and runner")
	}
	if _, err := a.VerifyRuntimeVersion(ctx); err != nil {
		return fmt.Errorf("adapters: Nmap runtime verification failed: %w", err)
	}
	return a.ReferenceAdapter.Initialize(ctx, logger)
}

func (a *NmapAdapter) VerifyRuntimeVersion(ctx context.Context) (RuntimeVersionInfo, error) {
	if a == nil || a.verify == nil {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: Nmap runtime verifier is unavailable")
	}
	actual, err := a.verify(ctx)
	if err != nil {
		return RuntimeVersionInfo{}, err
	}
	if actual.ScannerVersion == "" || actual.AdapterVersion != a.Version() || actual.ImageReference == "" || actual.ImageDigest == "" {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: Nmap runtime did not report a complete pinned identity")
	}
	return actual, nil
}

func (a *NmapAdapter) ValidateConfig(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg struct {
		Ports              string `json:"ports,omitempty"`
		MaxRate            int    `json:"max_rate,omitempty"`
		HostTimeoutSeconds int    `json:"host_timeout_seconds,omitempty"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("adapters: invalid Nmap configuration: %w", err)
	}
	if cfg.MaxRate > 100 {
		return fmt.Errorf("adapters: Nmap max_rate exceeds safe ceiling (100)")
	}
	if cfg.HostTimeoutSeconds > 300 {
		return fmt.Errorf("adapters: Nmap host_timeout_seconds exceeds safe ceiling (300)")
	}
	return nil
}

func (a *NmapAdapter) executeReport(ctx context.Context, task Task) (Result, error) {
	if err := a.ValidateConfig(task.Payload); err != nil {
		return Result{}, err
	}
	runtime, err := a.VerifyRuntimeVersion(ctx)
	if err != nil {
		return Result{}, err
	}
	started := time.Now().UTC()
	report, err := a.run(ctx, task)
	completed := time.Now().UTC()
	if err != nil {
		return Result{}, err
	}
	return NormalizeNmapXMLReport(task, report, runtime.ScannerVersion, started, completed)
}

var _ ScannerAdapter = (*NmapAdapter)(nil)
