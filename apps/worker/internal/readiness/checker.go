package readiness

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"go.uber.org/zap"
)

// SystemReadinessReport provides comprehensive operational diagnostics across system and scanners.
type SystemReadinessReport struct {
	ApplicationStatus Status                 `json:"application_status"` // Overall worker process status
	Scanners          map[string]Status      `json:"scanners"`           // Individual scanner availability
	Probes            []ProbeResult          `json:"probes"`             // Full probe outcomes
	EvaluatedAt       time.Time              `json:"evaluated_at"`
	TotalDuration     time.Duration          `json:"total_duration_ms"`
}

// PublicHealthSummary provides a sanitized, privacy-safe health summary for public probes (/healthz, /readyz).
// It strips all internal paths, image digests, catalog hashes, and stack traces.
type PublicHealthSummary struct {
	Status           string    `json:"status"`            // "ok", "degraded", "down"
	ReadyScanners    []string  `json:"ready_scanners"`    // Whitelist of operational scanner IDs
	DegradedScanners []string  `json:"degraded_scanners"` // Scanner IDs temporarily unavailable
	CheckedAt        time.Time `json:"checked_at"`
}

// Checker coordinates and evaluates readiness probes across the worker system and individual scanners.
type Checker struct {
	mu            sync.RWMutex
	systemProbes  []Probe
	scannerProbes map[string][]Probe
	logger        *zap.Logger
}

func NewChecker(logger *zap.Logger) *Checker {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Checker{
		scannerProbes: make(map[string][]Probe),
		logger:        logger,
	}
}

// RegisterSystemProbe registers a probe governing core worker prerequisites (OCI runtime, workspace).
func (c *Checker) RegisterSystemProbe(probe Probe) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.systemProbes = append(c.systemProbes, probe)
}

// RegisterScannerProbe registers a probe specific to a single scanner engine.
func (c *Checker) RegisterScannerProbe(scannerID string, probe Probe) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scannerProbes[scannerID] = append(c.scannerProbes[scannerID], probe)
}

// CheckScanner evaluates readiness of an individual scanner independently.
func (c *Checker) CheckScanner(ctx context.Context, scannerID string) (Status, []ProbeResult) {
	c.mu.RLock()
	probes, exists := c.scannerProbes[scannerID]
	c.mu.RUnlock()

	if !exists || len(probes) == 0 {
		res := ProbeResult{
			Name:      scannerID + "_registration",
			Target:    scannerID,
			Status:    StatusUnavailable,
			Message:   "scanner has no registered readiness probes",
			Error:     "unregistered scanner",
			CheckedAt: time.Now(),
		}
		return StatusUnavailable, []ProbeResult{res}
	}

	results := make([]ProbeResult, 0, len(probes))
	overall := StatusReady

	for _, probe := range probes {
		res := probe.Check(ctx)
		results = append(results, res)
		if res.Status == StatusUnavailable {
			overall = StatusUnavailable
			c.logProbeFailure(res)
		} else if res.Status == StatusDegraded && overall != StatusUnavailable {
			overall = StatusDegraded
		}
	}

	return overall, results
}

// IsScannerReady returns true if all probes for the specified scanner evaluate to StatusReady.
func (c *Checker) IsScannerReady(ctx context.Context, scannerID string) bool {
	status, _ := c.CheckScanner(ctx, scannerID)
	return status == StatusReady
}

// EvaluateAll executes all system and scanner probes, aggregating system and individual statuses.
func (c *Checker) EvaluateAll(ctx context.Context) SystemReadinessReport {
	start := time.Now()
	c.mu.RLock()
	sysProbes := append([]Probe(nil), c.systemProbes...)
	scannerMap := make(map[string][]Probe, len(c.scannerProbes))
	for k, v := range c.scannerProbes {
		scannerMap[k] = append([]Probe(nil), v...)
	}
	c.mu.RUnlock()

	allResults := make([]ProbeResult, 0, len(sysProbes)+len(scannerMap)*2)
	systemHealthy := true

	// 1. Run system probes
	for _, probe := range sysProbes {
		res := probe.Check(ctx)
		allResults = append(allResults, res)
		if res.Status != StatusReady {
			systemHealthy = false
			c.logProbeFailure(res)
		}
	}

	// 2. Run scanner probes
	scannerStatuses := make(map[string]Status, len(scannerMap))
	hasReadyScanner := false
	allScannersUnavailable := len(scannerMap) > 0

	// Sort scanner IDs for deterministic evaluation order
	scannerIDs := make([]string, 0, len(scannerMap))
	for id := range scannerMap {
		scannerIDs = append(scannerIDs, id)
	}
	sort.Strings(scannerIDs)

	for _, id := range scannerIDs {
		probes := scannerMap[id]
		scStatus := StatusReady
		for _, probe := range probes {
			res := probe.Check(ctx)
			allResults = append(allResults, res)
			if res.Status == StatusUnavailable {
				scStatus = StatusUnavailable
				c.logProbeFailure(res)
			} else if res.Status == StatusDegraded && scStatus != StatusUnavailable {
				scStatus = StatusDegraded
			}
		}
		scannerStatuses[id] = scStatus
		if scStatus == StatusReady {
			hasReadyScanner = true
			allScannersUnavailable = false
		} else if scStatus == StatusDegraded {
			allScannersUnavailable = false
		}
	}

	// 3. Determine Application Status (distinguishing system health from scanner availability)
	var appStatus Status
	if !systemHealthy {
		appStatus = StatusUnavailable
	} else if len(scannerMap) > 0 && allScannersUnavailable {
		appStatus = StatusDegraded
	} else if hasReadyScanner || len(scannerMap) == 0 {
		appStatus = StatusReady
	} else {
		appStatus = StatusDegraded
	}

	return SystemReadinessReport{
		ApplicationStatus: appStatus,
		Scanners:          scannerStatuses,
		Probes:            allResults,
		EvaluatedAt:       start,
		TotalDuration:     time.Since(start),
	}
}

// PublicSummary sanitizes internal diagnostics into a public-safe view.
func (c *Checker) PublicSummary(report SystemReadinessReport) PublicHealthSummary {
	var ready, degraded []string
	for id, status := range report.Scanners {
		if status == StatusReady {
			ready = append(ready, id)
		} else {
			degraded = append(degraded, id)
		}
	}
	sort.Strings(ready)
	sort.Strings(degraded)

	pubStatus := "down"
	if report.ApplicationStatus == StatusReady {
		if len(degraded) > 0 {
			pubStatus = "degraded"
		} else {
			pubStatus = "ok"
		}
	} else if report.ApplicationStatus == StatusDegraded {
		pubStatus = "degraded"
	}

	return PublicHealthSummary{
		Status:           pubStatus,
		ReadyScanners:    ready,
		DegradedScanners: degraded,
		CheckedAt:        report.EvaluatedAt,
	}
}

func (c *Checker) logProbeFailure(res ProbeResult) {
	c.logger.Warn("readiness probe failure detected",
		zap.String("probe_name", res.Name),
		zap.String("target", res.Target),
		zap.String("status", string(res.Status)),
		zap.String("message", res.Message),
		zap.String("error", res.Error),
		zap.Duration("duration_ms", res.Duration),
	)
}

// NewDefaultChecker initializes a standard readiness checker with system and registered adapter probes.
func NewDefaultChecker(registry *adapters.Registry, lookPathFn func(string) (string, error), catalogPath, workspaceDir string, logger *zap.Logger) *Checker {
	checker := NewChecker(logger)

	// System Probes
	checker.RegisterSystemProbe(NewOCIEngineProbe(lookPathFn))
	checker.RegisterSystemProbe(NewWorkspacePermissionsProbe(workspaceDir))

	// Adapter & Scanner Probes from Registry
	if registry != nil {
		for _, name := range registry.Names() {
			meta, ok := registry.Metadata(name)
			if !ok {
				continue
			}
			adapter, _ := registry.GetAdapter(name)

			// 1. Adapter lifecycle probe
			checker.RegisterScannerProbe(name, NewScannerAdapterProbe(name, adapter, meta.VersionPolicy))

			// 2. Container image probe if required
			if meta.Capabilities.RequiresSandbox && meta.VersionPolicy.ImageReference != "" {
				checker.RegisterScannerProbe(name, NewContainerImageProbe(name, meta.VersionPolicy.ImageReference, meta.VersionPolicy.ImageDigest, nil))
			}

			// 3. Nuclei template catalog probe
			if name == adapters.ScannerNuclei && catalogPath != "" {
				checker.RegisterScannerProbe(name, NewTemplateCatalogProbe(name, catalogPath))
			}
		}
	}

	return checker
}
