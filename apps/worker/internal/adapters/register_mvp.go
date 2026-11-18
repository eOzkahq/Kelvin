package adapters

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
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

	PinnedNmapScannerVersion = "7.95"
	PinnedNmapAdapterVersion = "1.0.0"
	PinnedNmapImageReference = "ghcr.io/eozkahq/kelvin/scanner-nmap:7.95@sha256:4a38dfc6d996e382d3345f1bce8b33534a029a242f3ea99d5a6b0c2a7e75e114"
	PinnedNmapImageDigest    = "sha256:4a38dfc6d996e382d3345f1bce8b33534a029a242f3ea99d5a6b0c2a7e75e114"
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
	info := RuntimeVersionInfo{
		ScannerVersion:         PinnedNucleiScannerVersion,
		AdapterVersion:         PinnedNucleiAdapterVersion,
		ImageReference:         PinnedNucleiImageReference,
		ImageDigest:            PinnedNucleiImageDigest,
		TemplateCatalogVersion: PinnedNucleiTemplateCatalogVersion,
		TemplateCatalogDigest:  PinnedNucleiTemplateCatalogDigest,
	}
	if lock, err := manifest.LoadCanonicalLock("deploy/scanners/images.lock.json"); err == nil && lock != nil {
		if lock.Status == manifest.StatusCertified || lock.Status == "released" {
			if img, ok := lock.Images["nuclei"]; ok {
				if img.Version != nil && *img.Version != "" {
					info.ScannerVersion = *img.Version
				}
				if img.KelvinDigest != nil && *img.KelvinDigest != "" {
					info.ImageDigest = *img.KelvinDigest
				}
				if img.KelvinImage != nil && *img.KelvinImage != "" {
					ref := *img.KelvinImage
					if info.ImageDigest != "" && !strings.Contains(ref, "@") {
						ref = ref + "@" + info.ImageDigest
					}
					info.ImageReference = ref
				}
				if img.TemplateCatalogDigest != nil && *img.TemplateCatalogDigest != "" {
					info.TemplateCatalogDigest = *img.TemplateCatalogDigest
				}
			}
		}
	}
	return info, nil
}

// DefaultZAPVerifier returns the pinned, locked version policy for OWASP ZAP baseline.
func DefaultZAPVerifier(_ context.Context) (RuntimeVersionInfo, error) {
	info := RuntimeVersionInfo{
		ScannerVersion: PinnedZAPScannerVersion,
		AdapterVersion: PinnedZAPAdapterVersion,
		ImageReference: PinnedZAPImageReference,
		ImageDigest:    PinnedZAPImageDigest,
	}
	if lock, err := manifest.LoadCanonicalLock("deploy/scanners/images.lock.json"); err == nil && lock != nil {
		if lock.Status == manifest.StatusCertified || lock.Status == "released" {
			if img, ok := lock.Images["zap"]; ok {
				if img.Version != nil && *img.Version != "" {
					info.ScannerVersion = *img.Version
				}
				if img.KelvinDigest != nil && *img.KelvinDigest != "" {
					info.ImageDigest = *img.KelvinDigest
				}
				if img.KelvinImage != nil && *img.KelvinImage != "" {
					ref := *img.KelvinImage
					if info.ImageDigest != "" && !strings.Contains(ref, "@") {
						ref = ref + "@" + info.ImageDigest
					}
					info.ImageReference = ref
				}
			}
		}
	}
	return info, nil
}

// DefaultNmapVerifier returns the pinned, locked version policy for Nmap.
func DefaultNmapVerifier(_ context.Context) (RuntimeVersionInfo, error) {
	info := RuntimeVersionInfo{
		ScannerVersion: PinnedNmapScannerVersion,
		AdapterVersion: PinnedNmapAdapterVersion,
		ImageReference: PinnedNmapImageReference,
		ImageDigest:    PinnedNmapImageDigest,
	}
	if lock, err := manifest.LoadCanonicalLock("deploy/scanners/images.lock.json"); err == nil && lock != nil {
		if lock.Status == manifest.StatusCertified || lock.Status == "released" {
			if img, ok := lock.Images["nmap"]; ok {
				if img.Version != nil && *img.Version != "" {
					info.ScannerVersion = *img.Version
				}
				if img.KelvinDigest != nil && *img.KelvinDigest != "" {
					info.ImageDigest = *img.KelvinDigest
				}
				if img.KelvinImage != nil && *img.KelvinImage != "" {
					ref := *img.KelvinImage
					if info.ImageDigest != "" && !strings.Contains(ref, "@") {
						ref = ref + "@" + info.ImageDigest
					}
					info.ImageReference = ref
				}
			}
		}
	}
	return info, nil
}

// NewOCINmapRunner creates a runner that executes Nmap inside the isolated OCI container sandbox.
func NewOCINmapRunner(executor sandbox.Executor) NmapReportRunner {
	return NewOCINmapRunnerWithScope(executor, DefaultScopePolicyProvider)
}

// NewOCINmapRunnerWithScope creates a runner that validates scope bounds before executing Nmap.
func NewOCINmapRunnerWithScope(executor sandbox.Executor, policyProvider ScopePolicyProvider) NmapReportRunner {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	return func(ctx context.Context, task Task) ([]byte, error) {
		if executor == nil {
			return nil, errors.New("adapters: sandbox executor is unavailable")
		}
		if pol, err := policyProvider(ctx, task); err == nil {
			if _, _, err := pol.Validate(ctx, task.Target); err != nil {
				return nil, fmt.Errorf("adapters: target %q rejected by scope policy: %w", task.Target, err)
			}
		}
		imgRef := PinnedNmapImageReference
		imgDigest := PinnedNmapImageDigest
		if lock, err := manifest.LoadCanonicalLock("deploy/scanners/images.lock.json"); err == nil && lock != nil {
			if (lock.Status == manifest.StatusCertified || lock.Status == "released") && lock.Images["nmap"].KelvinImage != nil {
				imgRef = *lock.Images["nmap"].KelvinImage
				if lock.Images["nmap"].KelvinDigest != nil {
					imgDigest = *lock.Images["nmap"].KelvinDigest
					if !strings.Contains(imgRef, "@") {
						imgRef = imgRef + "@" + imgDigest
					}
				}
			}
		}
		targetHost := task.Target
		if u, err := url.Parse(task.Target); err == nil && u.Hostname() != "" {
			targetHost = u.Hostname()
		}
		args := []string{
			"-sT",
			"-Pn",
			"-p", "1-1024",
			"-sV",
			"--version-intensity", "2",
			"-oX", "-",
			"--max-rate", "50",
			"--host-timeout", "60s",
			targetHost,
		}
		spec := sandbox.Spec{
			Scanner:     "nmap",
			Image:       imgRef,
			ImageDigest: imgDigest,
			Invocation: sandbox.ProcessInvocation{
				Executable: "/usr/bin/nmap",
				Args:       args,
			},
			Labels:          map[string]string{"scanner": "nmap"},
			User:            "10001:10001",
			ReadOnlyRootfs:  true,
			SecurityOpt:     []string{"no-new-privileges"},
			CapDrop:         []string{"ALL"},
			Deadline:        task.HardDeadline,
			PIDsLimit:       256,
			NetworkDisabled: true,
		}
		if task.EgressProxy != "" {
			spec.NetworkDisabled = false
			spec.EgressProxy = task.EgressProxy
		}
		res, err := executor.Execute(ctx, spec)
		if err != nil {
			return nil, err
		}
		return []byte(res.Stdout), nil
	}
}

// NewOCINucleiRunner creates a runner that executes Nuclei inside the isolated OCI container sandbox.
func NewOCINucleiRunner(executor sandbox.Executor) NucleiReportRunner {
	return NewOCINucleiRunnerWithScope(executor, DefaultScopePolicyProvider)
}

// NewOCINucleiRunnerWithScope creates a runner that validates scope bounds before executing Nuclei.
func NewOCINucleiRunnerWithScope(executor sandbox.Executor, policyProvider ScopePolicyProvider) NucleiReportRunner {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	return func(ctx context.Context, task Task) ([]byte, error) {
		if executor == nil {
			return nil, errors.New("adapters: sandbox executor is unavailable")
		}
		if pol, err := policyProvider(ctx, task); err == nil {
			if _, _, err := pol.Validate(ctx, task.Target); err != nil {
				return nil, fmt.Errorf("adapters: target %q rejected by scope policy: %w", task.Target, err)
			}
		}
		imgRef := PinnedNucleiImageReference
		imgDigest := PinnedNucleiImageDigest
		if lock, err := manifest.LoadCanonicalLock("deploy/scanners/images.lock.json"); err == nil && lock != nil {
			if (lock.Status == manifest.StatusCertified || lock.Status == "released") && lock.Images["nuclei"].KelvinImage != nil {
				imgRef = *lock.Images["nuclei"].KelvinImage
				if lock.Images["nuclei"].KelvinDigest != nil {
					imgDigest = *lock.Images["nuclei"].KelvinDigest
					if !strings.Contains(imgRef, "@") {
						imgRef = imgRef + "@" + imgDigest
					}
				}
			}
		}
		spec := sandbox.Spec{
			Scanner:        "nuclei",
			Image:          imgRef,
			ImageDigest:    imgDigest,
			Invocation: sandbox.ProcessInvocation{
				Executable: "/nuclei",
				Args:       BuildNucleiArgs(task),
			},
			Labels:          map[string]string{"scanner": "nuclei"},
			User:            "10001:10001",
			ReadOnlyRootfs:  true,
			SecurityOpt:     []string{"no-new-privileges"},
			CapDrop:         []string{"ALL"},
			Deadline:        task.HardDeadline,
			PIDsLimit:       256,
			NetworkDisabled: true,
		}
		if task.EgressProxy != "" {
			spec.NetworkDisabled = false
			spec.EgressProxy = task.EgressProxy
		}
		res, err := executor.Execute(ctx, spec)
		if err != nil {
			return nil, err
		}
		return []byte(res.Stdout), nil
	}
}

// NewOCIZAPRunner creates a runner that executes ZAP baseline or active scan inside the isolated OCI container sandbox.
func NewOCIZAPRunner(executor sandbox.Executor) ZAPReportRunner {
	return NewOCIZAPRunnerWithScope(executor, DefaultScopePolicyProvider)
}

// NewOCIZAPRunnerWithScope creates a runner that validates scope bounds before executing ZAP.
func NewOCIZAPRunnerWithScope(executor sandbox.Executor, policyProvider ScopePolicyProvider) ZAPReportRunner {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	return func(ctx context.Context, task Task) ([]byte, error) {
		if executor == nil {
			return nil, errors.New("adapters: sandbox executor is unavailable")
		}
		if pol, err := policyProvider(ctx, task); err == nil {
			if _, _, err := pol.Validate(ctx, task.Target); err != nil {
				return nil, fmt.Errorf("adapters: target %q rejected by scope policy: %w", task.Target, err)
			}
		}
		imgRef := PinnedZAPImageReference
		imgDigest := PinnedZAPImageDigest
		if lock, err := manifest.LoadCanonicalLock("deploy/scanners/images.lock.json"); err == nil && lock != nil {
			if (lock.Status == manifest.StatusCertified || lock.Status == "released") && lock.Images["zap"].KelvinImage != nil {
				imgRef = *lock.Images["zap"].KelvinImage
				if lock.Images["zap"].KelvinDigest != nil {
					imgDigest = *lock.Images["zap"].KelvinDigest
					if !strings.Contains(imgRef, "@") {
						imgRef = imgRef + "@" + imgDigest
					}
				}
			}
		}
		executable := "/zap/zap-baseline.py"
		cfg, _ := zapConfig(task.Payload)
		if cfg.ExecutionMode == "ACTIVE" || (cfg.ZAP != nil && cfg.ZAP.ActiveScan) {
			profile, err := GetAssessmentProfile(task.ProfileID)
			if err != nil || profile.TrafficLevel != "active" || !profile.AdminSignoffRequired {
				return nil, fmt.Errorf("adapters: ZAP active scanning requires explicit authorization under an active assessment profile (got profile: %q)", task.ProfileID)
			}
			executable = "/zap/zap-full-scan.py"
		}
		spec := sandbox.Spec{
			Scanner:          "zap",
			Image:            imgRef,
			ImageDigest:      imgDigest,
			Invocation: sandbox.ProcessInvocation{
				Executable: executable,
				Args:       []string{"-t", task.Target, "-J", "/tmp/kelvin-zap-report.json"},
			},
			Labels:           map[string]string{"scanner": "zap"},
			User:             "10001:10001",
			ReadOnlyRootfs:   true,
			SecurityOpt:      []string{"no-new-privileges"},
			CapDrop:          []string{"ALL"},
			CaptureZAPReport: true,
			Deadline:         task.HardDeadline,
			PIDsLimit:        256,
			NetworkDisabled:  true,
		}
		if task.EgressProxy != "" {
			spec.NetworkDisabled = false
			spec.EgressProxy = task.EgressProxy
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
	nucleiInfo, _ := DefaultNucleiVerifier(context.Background())
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
			ScannerVersion:         nucleiInfo.ScannerVersion,
			ImageReference:         nucleiInfo.ImageReference,
			ImageDigest:            nucleiInfo.ImageDigest,
			TemplateCatalogVersion: nucleiInfo.TemplateCatalogVersion,
			TemplateCatalogDigest:  nucleiInfo.TemplateCatalogDigest,
		},
	}
	nucleiRunner := NewOCINucleiRunner(executor)
	if err := registry.RegisterAdapter(nucleiMetadata, func() ScannerAdapter {
		return NewVerifiedNucleiAdapter(DefaultNucleiVerifier, nucleiRunner)
	}); err != nil {
		return err
	}

	// 3. OWASP ZAP Baseline Adapter with pinned metadata and sandbox runner
	zapInfo, _ := DefaultZAPVerifier(context.Background())
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
			ScannerVersion: zapInfo.ScannerVersion,
			ImageReference: zapInfo.ImageReference,
			ImageDigest:    zapInfo.ImageDigest,
		},
	}
	zapRunner := NewOCIZAPRunner(executor)
	if err := registry.RegisterAdapter(zapMetadata, func() ScannerAdapter {
		return NewVerifiedZAPBaselineAdapter(DefaultZAPVerifier, zapRunner)
	}); err != nil {
		return err
	}

	// 4. Nmap Adapter with pinned metadata and sandbox runner
	nmapInfo, _ := DefaultNmapVerifier(context.Background())
	nmapMetadata := Metadata{
		ID:               ScannerNmap,
		DisplayName:      "Nmap Network Scanner",
		Version:          PinnedNmapAdapterVersion,
		SupportedTargets: []string{"hostname", "ip", "url"},
		Capabilities: Capabilities{
			CheckCategories:      []string{"discovery", "port_scan", "service_detection"},
			SupportedTargetTypes: []string{"hostname", "ip", "url"},
			SupportedProtocols:   []string{"tcp", "http", "https"},
			PassiveOnly:          false,
			ActiveScanning:       true,
			RequiresNetwork:      true,
			SupportsCancel:       true,
			RequiresSandbox:      true,
			MaxConcurrency:       1,
			MaxRequestRate:       10,
			MaxRequests:          1000,
		},
		ConfigVersion: ScannerConfigVersion,
		VersionPolicy: VersionPolicy{
			ScannerVersion: nmapInfo.ScannerVersion,
			ImageReference: nmapInfo.ImageReference,
			ImageDigest:    nmapInfo.ImageDigest,
		},
	}
	nmapRunner := NewOCINmapRunner(executor)
	if err := registry.RegisterAdapter(nmapMetadata, func() ScannerAdapter {
		return NewVerifiedNmapAdapter(DefaultNmapVerifier, nmapRunner)
	}); err != nil {
		return err
	}

	return nil
}
