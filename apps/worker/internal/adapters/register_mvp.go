package adapters

import (
	"context"
	"errors"
	"net/url"

	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"github.com/kelvin/kelvin/packages/common/scope"
)

const (
	PinnedNucleiScannerVersion         = "3.3.7"
	PinnedNucleiAdapterVersion         = "1.0.0"
	PinnedNucleiImageReference         = "projectdiscovery/nuclei:v3.3.7@sha256:bb1a9829910d9faef8dcf16ad8dc94c50be4ce9356ef30ef834c2b9fae068b55"
	PinnedNucleiImageDigest            = "sha256:bb1a9829910d9faef8dcf16ad8dc94c50be4ce9356ef30ef834c2b9fae068b55"
	PinnedNucleiTemplateCatalogVersion = "kelvin.safe.web.v1"
	PinnedNucleiTemplateCatalogDigest  = "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"

	PinnedZAPScannerVersion = "2.15.0"
	PinnedZAPAdapterVersion = "1.0.0"
	PinnedZAPImageReference = "ghcr.io/zaproxy/zaproxy:2.15.0@sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919"
	PinnedZAPImageDigest    = "sha256:d9b23b169527be63660fb1e57c6b9eb97cf1e2c9ef806dc5e7e3e7f53cfc0919"
)

// DefaultScopePolicyProvider provides target resolution and scope bounds for network adapters.
func DefaultScopePolicyProvider(_ context.Context, task Task) (scope.Policy, error) {
	target := task.Target
	u, err := url.Parse(target)
	hostname := target
	if err == nil && u.Hostname() != "" {
		hostname = u.Hostname()
	}
	return scope.NewPolicy([]string{hostname}, nil, nil)
}

// DefaultNucleiVerifier returns the pinned, locked version policy for Nuclei.
func DefaultNucleiVerifier(_ context.Context) (RuntimeVersionInfo, error) {
	return RuntimeVersionInfo{
		ScannerVersion:         PinnedNucleiScannerVersion,
		AdapterVersion:         PinnedNucleiAdapterVersion,
		ImageReference:         PinnedNucleiImageReference,
		ImageDigest:            PinnedNucleiImageDigest,
		TemplateCatalogVersion: PinnedNucleiTemplateCatalogVersion,
		TemplateCatalogDigest:  PinnedNucleiTemplateCatalogDigest,
	}, nil
}

// DefaultZAPVerifier returns the pinned, locked version policy for OWASP ZAP baseline.
func DefaultZAPVerifier(_ context.Context) (RuntimeVersionInfo, error) {
	return RuntimeVersionInfo{
		ScannerVersion: PinnedZAPScannerVersion,
		AdapterVersion: PinnedZAPAdapterVersion,
		ImageReference: PinnedZAPImageReference,
		ImageDigest:    PinnedZAPImageDigest,
	}, nil
}

// NewOCINucleiRunner creates a runner that executes Nuclei inside the isolated OCI container sandbox.
func NewOCINucleiRunner(executor sandbox.Executor) NucleiReportRunner {
	return func(ctx context.Context, task Task) ([]byte, error) {
		if executor == nil {
			return nil, errors.New("adapters: sandbox executor is unavailable")
		}
		spec := sandbox.Spec{
			Scanner:        "nuclei",
			Image:          PinnedNucleiImageReference,
			ImageDigest:    PinnedNucleiImageDigest,
			Invocation: sandbox.ProcessInvocation{
				Executable: "/nuclei",
				Args:       []string{"-u", task.Target, "-jsonl", "-silent"},
			},
			Labels:          map[string]string{"scanner": "nuclei"},
			User:            "10001:10001",
			ReadOnlyRootfs:  true,
			SecurityOpt:     []string{"no-new-privileges"},
			CapDrop:         []string{"ALL"},
			Deadline:        task.HardDeadline,
			NetworkDisabled: true,
		}
		res, err := executor.Execute(ctx, spec)
		if err != nil {
			return nil, err
		}
		return []byte(res.Stdout), nil
	}
}

// NewOCIZAPRunner creates a runner that executes ZAP baseline inside the isolated OCI container sandbox.
func NewOCIZAPRunner(executor sandbox.Executor) ZAPReportRunner {
	return func(ctx context.Context, task Task) ([]byte, error) {
		if executor == nil {
			return nil, errors.New("adapters: sandbox executor is unavailable")
		}
		spec := sandbox.Spec{
			Scanner:          "zap",
			Image:            PinnedZAPImageReference,
			ImageDigest:      PinnedZAPImageDigest,
			Invocation: sandbox.ProcessInvocation{
				Executable: "/zap/zap-baseline.py",
				Args:       []string{"-t", task.Target, "-J", "/tmp/kelvin-zap-report.json"},
			},
			Labels:           map[string]string{"scanner": "zap"},
			User:             "10001:10001",
			ReadOnlyRootfs:   true,
			SecurityOpt:      []string{"no-new-privileges"},
			CapDrop:          []string{"ALL"},
			CaptureZAPReport: true,
			Deadline:         task.HardDeadline,
			NetworkDisabled:  true,
		}
		res, err := executor.Execute(ctx, spec)
		if err != nil {
			return nil, err
		}
		return res.Findings, nil
	}
}

// RegisterDefaultAdapters registers all supported MVP scanner adapters:
// HTTP Preflight, HTTP Security Headers, TLS Assessor, Nuclei, and OWASP ZAP Baseline.
func RegisterDefaultAdapters(registry *Registry, executor sandbox.Executor) error {
	policyProvider := DefaultScopePolicyProvider

	// 1. Built-in network adapters (no container sandbox needed)
	if err := registry.Register(NewHTTPPreflightAdapter(policyProvider)); err != nil {
		return err
	}
	if err := registry.Register(NewHTTPSecurityHeadersAdapter(policyProvider)); err != nil {
		return err
	}
	if err := registry.Register(NewTLSAssessmentAdapter(policyProvider, nil)); err != nil {
		return err
	}

	// 2. Nuclei Adapter with pinned metadata and sandbox runner
	nucleiMetadata := Metadata{
		ID:               ScannerNuclei,
		DisplayName:      "Nuclei Vulnerability Scanner",
		Version:          PinnedNucleiAdapterVersion,
		SupportedTargets: []string{"url"},
		Capabilities: Capabilities{
			CheckCategories:      []string{"vulnerability_scanning", "misconfiguration"},
			SupportedTargetTypes: []string{"url"},
			SupportedProtocols:   []string{"http", "https"},
			PassiveOnly:          false,
			ActiveScanning:       true,
			RequiresNetwork:      true,
			SupportsCancel:       true,
			RequiresSandbox:      true,
			MaxConcurrency:       2,
			MaxRequestRate:       5,
			MaxRequests:          1000,
		},
		ConfigVersion: ScannerConfigVersion,
		VersionPolicy: VersionPolicy{
			ScannerVersion:         PinnedNucleiScannerVersion,
			ImageReference:         PinnedNucleiImageReference,
			ImageDigest:            PinnedNucleiImageDigest,
			TemplateCatalogVersion: PinnedNucleiTemplateCatalogVersion,
			TemplateCatalogDigest:  PinnedNucleiTemplateCatalogDigest,
		},
	}
	nucleiRunner := NewOCINucleiRunner(executor)
	if err := registry.RegisterAdapter(nucleiMetadata, func() ScannerAdapter {
		return NewVerifiedNucleiAdapter(DefaultNucleiVerifier, nucleiRunner)
	}); err != nil {
		return err
	}

	// 3. OWASP ZAP Baseline Adapter with pinned metadata and sandbox runner
	zapMetadata := Metadata{
		ID:               ScannerZAPBaseline,
		DisplayName:      "OWASP ZAP Baseline Scanner",
		Version:          PinnedZAPAdapterVersion,
		SupportedTargets: []string{"url"},
		Capabilities: Capabilities{
			CheckCategories:      []string{"passive_web_application_security"},
			SupportedTargetTypes: []string{"url"},
			SupportedProtocols:   []string{"http", "https"},
			PassiveOnly:          true,
			ActiveScanning:       false,
			RequiresNetwork:      true,
			SupportsCancel:       true,
			RequiresSandbox:      true,
			MaxConcurrency:       2,
			MaxRequestRate:       1,
			MaxRequests:          250,
		},
		ConfigVersion: ScannerConfigVersion,
		VersionPolicy: VersionPolicy{
			ScannerVersion: PinnedZAPScannerVersion,
			ImageReference: PinnedZAPImageReference,
			ImageDigest:    PinnedZAPImageDigest,
		},
	}
	zapRunner := NewOCIZAPRunner(executor)
	if err := registry.RegisterAdapter(zapMetadata, func() ScannerAdapter {
		return NewVerifiedZAPBaselineAdapter(DefaultZAPVerifier, zapRunner)
	}); err != nil {
		return err
	}

	return nil
}
