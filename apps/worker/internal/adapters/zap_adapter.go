package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ZAPReportRunner returns the JSON report copied from a completed, bounded
// zap-baseline.py container run. Production wiring must source this from the
// worker OCI executor; tests can supply a deterministic fixture.
type ZAPReportRunner func(context.Context, Task) ([]byte, error)

// ZAPRuntimeVerifier must measure the actual image and executable identity.
// It is required because the current images.lock.json does not certify a
// released ZAP image.
type ZAPRuntimeVerifier func(context.Context) (RuntimeVersionInfo, error)

type ZAPBaselineAdapter struct {
	*ReferenceAdapter
	verify ZAPRuntimeVerifier
	run    ZAPReportRunner
}

func NewVerifiedZAPBaselineAdapter(verifier ZAPRuntimeVerifier, runner ZAPReportRunner) *ZAPBaselineAdapter {
	a := &ZAPBaselineAdapter{
		verify: verifier,
		run:    runner,
		ReferenceAdapter: &ReferenceAdapter{AdapterName: ScannerZAPBaseline, Caps: Capabilities{
			CheckCategories: []string{"passive_web_application_security"}, SupportedTargetTypes: []string{"url"},
			SupportedProtocols: []string{"http", "https"}, PassiveOnly: true, ActiveScanning: false,
			RequiresNetwork: true, SupportsCancel: true, RequiresSandbox: true,
			MaxConcurrency: 2, MaxRequestRate: 1, MaxRequests: 250,
		}},
	}
	a.ReferenceAdapter.Run = a.executeReport
	return a
}

func (a *ZAPBaselineAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a == nil || a.verify == nil || a.run == nil {
		return fmt.Errorf("adapters: ZAP adapter requires a runtime verifier and sandbox report runner")
	}
	if _, err := a.VerifyRuntimeVersion(ctx); err != nil {
		return fmt.Errorf("adapters: ZAP runtime verification failed: %w", err)
	}
	return a.ReferenceAdapter.Initialize(ctx, logger)
}

func (a *ZAPBaselineAdapter) VerifyRuntimeVersion(ctx context.Context) (RuntimeVersionInfo, error) {
	if a == nil || a.verify == nil {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: ZAP runtime verifier is unavailable")
	}
	actual, err := a.verify(ctx)
	if err != nil {
		return RuntimeVersionInfo{}, err
	}
	if actual.ScannerVersion == "" || actual.AdapterVersion != a.Version() || actual.ImageReference == "" || actual.ImageDigest == "" {
		return RuntimeVersionInfo{}, fmt.Errorf("adapters: ZAP runtime did not report a complete pinned identity")
	}
	return actual, nil
}

func (a *ZAPBaselineAdapter) ValidateConfig(raw json.RawMessage) error {
	config, err := zapConfig(raw)
	if err != nil {
		return err
	}
	if config.MaxConcurrency > 2 || config.RequestsPerSecond > 1 {
		return fmt.Errorf("adapters: ZAP configuration exceeds adapter resource limits")
	}
	return nil
}

func zapConfig(raw json.RawMessage) (ScannerConfigV1, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return DefaultScannerConfig(ScannerZAPBaseline)
	}
	config, err := DecodeScannerConfig(raw)
	if err != nil {
		return ScannerConfigV1{}, err
	}
	if config.ScannerID != ScannerZAPBaseline {
		return ScannerConfigV1{}, fmt.Errorf("adapters: config scanner_id does not match ZAP")
	}
	return config, nil
}

func (a *ZAPBaselineAdapter) executeReport(ctx context.Context, task Task) (Result, error) {
	if err := a.ValidateConfig(task.Payload); err != nil {
		return Result{}, err
	}
	cfg, _ := zapConfig(task.Payload)
	if cfg.ExecutionMode == "ACTIVE" || (cfg.ZAP != nil && cfg.ZAP.ActiveScan) {
		profile, err := GetAssessmentProfile(task.ProfileID)
		if err != nil || profile.TrafficLevel != "active" || !profile.AdminSignoffRequired {
			return Result{}, fmt.Errorf("adapters: ZAP active scanning requires explicit authorization under an active assessment profile (got profile: %q)", task.ProfileID)
		}
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
	return NormalizeZAPReport(task, report, runtime.ScannerVersion, started, completed)
}

var _ ScannerAdapter = (*ZAPBaselineAdapter)(nil)
