package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// NucleiReportRunner returns the raw JSONL output copied/streamed from a
// completed, bounded Nuclei container execution. Production wiring sources
// this from the worker OCI sandbox executor (stdout capture); tests can supply
// deterministic fixtures.
type NucleiReportRunner func(context.Context, Task) ([]byte, error)

// NucleiRuntimeVerifier measures the actual image and executable identity, as
// well as the template catalog identity.
type NucleiRuntimeVerifier func(context.Context) (RuntimeVersionInfo, error)

type NucleiAdapter struct {
	*ReferenceAdapter
	verify NucleiRuntimeVerifier
	run    NucleiReportRunner
}

func NewVerifiedNucleiAdapter(verifier NucleiRuntimeVerifier, runner NucleiReportRunner) *NucleiAdapter {
	a := &NucleiAdapter{
		verify: verifier,
		run:    runner,
		ReferenceAdapter: &ReferenceAdapter{AdapterName: ScannerNuclei, Caps: Capabilities{
			CheckCategories:    []string{"vulnerability_scanning", "misconfiguration"},
			SupportedTargetTypes: []string{"url"},
			SupportedProtocols: []string{"http", "https"},
			PassiveOnly:        false,
			ActiveScanning:     true,
			RequiresNetwork:    true,
			SupportsCancel:     true,
			RequiresSandbox:    true,
			MaxConcurrency:     2,
			MaxRequestRate:     5,
			MaxRequests:        1000,
		}},
	}
	a.ReferenceAdapter.Run = a.executeReport
	return a
}

func (a *NucleiAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a == nil || a.verify == nil || a.run == nil {
		return fmt.Errorf("adapters: Nuclei adapter requires a runtime verifier and runner")
	}
	if _, err := a.VerifyRuntimeVersion(ctx); err != nil {
		return fmt.Errorf("adapters: Nuclei runtime verification failed: %w", err)
	}
	return a.ReferenceAdapter.Initialize(ctx, logger)
}

func (a *NucleiAdapter) VerifyRuntimeVersion(ctx context.Context) (RuntimeVersionInfo, error) {
	if a == nil || a.verify == nil {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: Nuclei runtime verifier is unavailable")
	}
	actual, err := a.verify(ctx)
	if err != nil {
		return RuntimeVersionInfo{}, err
	}
	if actual.ScannerVersion == "" || actual.AdapterVersion != a.Version() || actual.ImageReference == "" || actual.ImageDigest == "" {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: Nuclei runtime did not report a complete pinned identity")
	}
	if actual.TemplateCatalogVersion != "kelvin.safe.web.v1" || actual.TemplateCatalogDigest == "" {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: Nuclei runtime did not report an approved template catalog identity")
	}
	if !digestPattern.MatchString(actual.TemplateCatalogDigest) {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: Nuclei runtime reported an invalid template catalog digest")
	}
	return actual, nil
}

func (a *NucleiAdapter) ValidateConfig(raw json.RawMessage) error {
	config, err := nucleiConfig(raw)
	if err != nil {
		return err
	}
	if config.MaxConcurrency > 2 || config.RequestsPerSecond > 5 {
		return fmt.Errorf("adapters: Nuclei configuration exceeds adapter resource limits")
	}
	return nil
}

func nucleiConfig(raw json.RawMessage) (ScannerConfigV1, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return DefaultScannerConfig(ScannerNuclei)
	}
	config, err := DecodeScannerConfig(raw)
	if err != nil {
		return ScannerConfigV1{}, err
	}
	if config.ScannerID != ScannerNuclei {
		return ScannerConfigV1{}, fmt.Errorf("adapters: config scanner_id does not match Nuclei")
	}
	return config, nil
}

func (a *NucleiAdapter) executeReport(ctx context.Context, task Task) (Result, error) {
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
	return NormalizeNucleiReport(task, report, runtime.ScannerVersion, runtime.TemplateCatalogVersion, runtime.TemplateCatalogDigest, started, completed)
}

var _ ScannerAdapter = (*NucleiAdapter)(nil)
