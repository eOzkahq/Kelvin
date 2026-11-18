package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
)

// Status represents the health state of a readiness probe or scanner.
type Status string

const (
	StatusReady       Status = "READY"
	StatusDegraded    Status = "DEGRADED"
	StatusUnavailable Status = "UNAVAILABLE"
)

// ProbeResult captures the outcome of an individual readiness verification probe.
type ProbeResult struct {
	Name        string            `json:"name"`
	Target      string            `json:"target"` // scanner ID, or system component ("oci", "workspace", "catalog")
	Status      Status            `json:"status"`
	Message     string            `json:"message"`
	Error       string            `json:"error,omitempty"`
	CheckedAt   time.Time         `json:"checked_at"`
	Duration    time.Duration     `json:"duration_ms"`
	Diagnostics map[string]string `json:"diagnostics,omitempty"` // Internal debug details (never exposed publicly)
}

// Probe evaluates the operational readiness of a system component or scanner.
type Probe interface {
	Name() string
	Target() string
	Check(ctx context.Context) ProbeResult
}

// FunctionProbe allows constructing lightweight probes from functions.
type FunctionProbe struct {
	ProbeName   string
	ProbeTarget string
	CheckFn     func(ctx context.Context) ProbeResult
}

func (f FunctionProbe) Name() string                     { return f.ProbeName }
func (f FunctionProbe) Target() string                   { return f.ProbeTarget }
func (f FunctionProbe) Check(ctx context.Context) ProbeResult { return f.CheckFn(ctx) }

// OCIEngineProbe verifies that the OCI container engine (Podman or Docker) is accessible.
type OCIEngineProbe struct {
	lookPathFn func(string) (string, error)
}

func NewOCIEngineProbe(lookPathFn func(string) (string, error)) *OCIEngineProbe {
	if lookPathFn == nil {
		lookPathFn = exec.LookPath
	}
	return &OCIEngineProbe{lookPathFn: lookPathFn}
}

func (p *OCIEngineProbe) Name() string   { return "oci_container_engine" }
func (p *OCIEngineProbe) Target() string { return "system" }

func (p *OCIEngineProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	for _, candidate := range []string{"podman", "docker"} {
		if path, err := p.lookPathFn(candidate); err == nil {
			return ProbeResult{
				Name:      p.Name(),
				Target:    p.Target(),
				Status:    StatusReady,
				Message:   fmt.Sprintf("OCI container engine %q accessible at %s", candidate, path),
				CheckedAt: start,
				Duration:  time.Since(start),
				Diagnostics: map[string]string{
					"engine": candidate,
					"path":   path,
				},
			}
		}
	}

	return ProbeResult{
		Name:      p.Name(),
		Target:    p.Target(),
		Status:    StatusUnavailable,
		Message:   "no OCI container engine (podman/docker) found in PATH",
		Error:     "sandbox: no OCI runtime (podman/docker) found",
		CheckedAt: start,
		Duration:  time.Since(start),
	}
}

// ImageInspector provides container image inspection against the host container engine.
type ImageInspector interface {
	InspectImage(ctx context.Context, imageRef string) (ImageInspectInfo, error)
}

type ImageInspectInfo struct {
	ImageReference string
	Digest         string
	Available      bool
	RepoDigests    []string
}

// MockImageInspector is a testable image inspector.
type MockImageInspector struct {
	InspectFn func(ctx context.Context, imageRef string) (ImageInspectInfo, error)
}

func (m MockImageInspector) InspectImage(ctx context.Context, imageRef string) (ImageInspectInfo, error) {
	if m.InspectFn != nil {
		return m.InspectFn(ctx, imageRef)
	}
	return ImageInspectInfo{}, fmt.Errorf("inspect not implemented")
}

// CommandRunner defines the signature for executing system commands.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// OCIImageInspector inspects container images against local OCI runtime storage (Podman or Docker).
type OCIImageInspector struct {
	runtime       string
	lookPathFn    func(string) (string, error)
	commandRunner CommandRunner
}

// NewOCIImageInspector creates a new OCIImageInspector.
// If lookPathFn is nil, exec.LookPath is used.
// If runner is nil, exec.CommandContext is used.
func NewOCIImageInspector(lookPathFn func(string) (string, error), runner CommandRunner) *OCIImageInspector {
	if lookPathFn == nil {
		lookPathFn = exec.LookPath
	}
	if runner == nil {
		runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			return cmd.CombinedOutput()
		}
	}
	return &OCIImageInspector{
		lookPathFn:    lookPathFn,
		commandRunner: runner,
	}
}

func (insp *OCIImageInspector) getRuntime() (string, error) {
	if insp.runtime != "" {
		return insp.runtime, nil
	}
	if explicit := os.Getenv("KELVIN_OCI_RUNTIME"); explicit != "" {
		if path, err := insp.lookPathFn(explicit); err == nil {
			insp.runtime = path
			return path, nil
		}
	}
	for _, candidate := range []string{"podman", "docker"} {
		if path, err := insp.lookPathFn(candidate); err == nil {
			insp.runtime = path
			return path, nil
		}
	}
	return "", fmt.Errorf("no OCI runtime (podman/docker) found")
}

func (insp *OCIImageInspector) InspectImage(ctx context.Context, imageRef string) (ImageInspectInfo, error) {
	runtime, err := insp.getRuntime()
	if err != nil {
		return ImageInspectInfo{ImageReference: imageRef, Available: false}, err
	}

	out, err := insp.commandRunner(ctx, runtime, "image", "inspect", imageRef)
	if err != nil && strings.Contains(imageRef, "@") {
		baseRef := strings.SplitN(imageRef, "@", 2)[0]
		if outFallback, errFallback := insp.commandRunner(ctx, runtime, "image", "inspect", baseRef); errFallback == nil {
			out = outFallback
			err = nil
		}
	}
	if err != nil {
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, "no such image") ||
			strings.Contains(outStr, "image not found") ||
			strings.Contains(outStr, "not found") ||
			strings.Contains(outStr, "could not find image") ||
			strings.Contains(outStr, "error response from daemon") {
			return ImageInspectInfo{
				ImageReference: imageRef,
				Available:      false,
			}, nil
		}
		// In case output indicates non-existence or exit code 125/1
		if len(out) > 0 {
			return ImageInspectInfo{
				ImageReference: imageRef,
				Available:      false,
			}, nil
		}
		return ImageInspectInfo{ImageReference: imageRef, Available: false}, fmt.Errorf("oci inspect error: %w", err)
	}

	var inspectList []struct {
		ID          string   `json:"Id"`
		Digest      string   `json:"Digest"`
		RepoDigests []string `json:"RepoDigests"`
	}

	if err := json.Unmarshal(out, &inspectList); err != nil {
		return ImageInspectInfo{ImageReference: imageRef, Available: false}, fmt.Errorf("failed to parse inspect output: %w", err)
	}

	if len(inspectList) == 0 {
		return ImageInspectInfo{ImageReference: imageRef, Available: false}, nil
	}

	entry := inspectList[0]
	digest := entry.Digest
	if digest == "" {
		for _, repoDigest := range entry.RepoDigests {
			if idx := strings.Index(repoDigest, "@"); idx != -1 {
				digest = repoDigest[idx+1:]
				break
			}
		}
	}
	if digest == "" {
		digest = entry.ID
	}

	return ImageInspectInfo{
		ImageReference: imageRef,
		Digest:         digest,
		Available:      true,
		RepoDigests:    entry.RepoDigests,
	}, nil
}

// ContainerImageProbe verifies that a required container image exists and matches version policy.
type ContainerImageProbe struct {
	scannerID string
	imageRef  string
	digest    string
	inspector ImageInspector
}

func NewContainerImageProbe(scannerID, imageRef, digest string, inspector ImageInspector) *ContainerImageProbe {
	return &ContainerImageProbe{
		scannerID: scannerID,
		imageRef:  imageRef,
		digest:    digest,
		inspector: inspector,
	}
}

func (p *ContainerImageProbe) Name() string   { return p.scannerID + "_container_image" }
func (p *ContainerImageProbe) Target() string { return p.scannerID }

func (p *ContainerImageProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	if p.imageRef == "" {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   "container image reference is not configured",
			Error:     "missing image reference",
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	inspector := p.inspector
	if inspector == nil {
		inspector = NewOCIImageInspector(nil, nil)
	}

	info, err := inspector.InspectImage(ctx, p.imageRef)
	if err != nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("OCI runtime unavailable to inspect image %s: %v", p.imageRef, err),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	if !info.Available {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("container image %q is not present on host; run 'podman pull %s' or build image before dispatch", p.imageRef, p.imageRef),
			Error:     "container image not present on host",
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	if p.digest != "" && info.Digest != "" && !strings.EqualFold(p.digest, info.Digest) {
		matchedRepo := false
		for _, rd := range info.RepoDigests {
			if strings.EqualFold(rd, p.digest) || strings.HasSuffix(strings.ToLower(rd), "@"+strings.ToLower(p.digest)) {
				matchedRepo = true
				break
			}
		}
		if !matchedRepo {
			if os.Getenv("KELVIN_ALLOW_LOCAL_IMAGE_DIGEST") == "true" {
				return ProbeResult{
					Name:      p.Name(),
					Target:    p.Target(),
					Status:    StatusReady,
					Message:   fmt.Sprintf("container image %s present on host (local digest %s)", p.imageRef, info.Digest),
					CheckedAt: start,
					Duration:  time.Since(start),
				}
			}
			return ProbeResult{
				Name:      p.Name(),
				Target:    p.Target(),
				Status:    StatusUnavailable,
				Message:   fmt.Sprintf("container image digest mismatch for %s: expected %s, got %s", p.imageRef, p.digest, info.Digest),
				Error:     fmt.Sprintf("expected digest %s, got %s", p.digest, info.Digest),
				CheckedAt: start,
				Duration:  time.Since(start),
			}
		}
	}

	return ProbeResult{
		Name:      p.Name(),
		Target:    p.Target(),
		Status:    StatusReady,
		Message:   fmt.Sprintf("container image %s verified", p.imageRef),
		CheckedAt: start,
		Duration:  time.Since(start),
		Diagnostics: map[string]string{
			"image_ref": p.imageRef,
			"digest":    info.Digest,
		},
	}
}

// TemplateCatalogProbe verifies the presence and SHA-256 integrity of a curated template catalog.
type TemplateCatalogProbe struct {
	scannerID   string
	catalogPath string
}

func NewTemplateCatalogProbe(scannerID, catalogPath string) *TemplateCatalogProbe {
	return &TemplateCatalogProbe{
		scannerID:   scannerID,
		catalogPath: catalogPath,
	}
}

func (p *TemplateCatalogProbe) Name() string   { return p.scannerID + "_template_catalog" }
func (p *TemplateCatalogProbe) Target() string { return p.scannerID }

func (p *TemplateCatalogProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	if p.catalogPath == "" {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   "template catalog path is not configured",
			Error:     "empty catalog path",
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	manifest, digest, err := adapters.LoadCuratedCatalog(p.catalogPath)
	if err != nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("curated catalog verification failed for %s", p.catalogPath),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	return ProbeResult{
		Name:      p.Name(),
		Target:    p.Target(),
		Status:    StatusReady,
		Message:   fmt.Sprintf("curated catalog %s (v%s) verified with %d templates", manifest.CatalogID, manifest.Version, len(manifest.Templates)),
		CheckedAt: start,
		Duration:  time.Since(start),
		Diagnostics: map[string]string{
			"catalog_id": manifest.CatalogID,
			"version":    manifest.Version,
			"digest":     digest,
			"templates":  fmt.Sprintf("%d", len(manifest.Templates)),
		},
	}
}

// WorkspacePermissionsProbe verifies that the ephemeral scratch/workspace directory is writable.
type WorkspacePermissionsProbe struct {
	workspaceDir string
}

func NewWorkspacePermissionsProbe(workspaceDir string) *WorkspacePermissionsProbe {
	if workspaceDir == "" {
		workspaceDir = os.TempDir()
	}
	return &WorkspacePermissionsProbe{workspaceDir: workspaceDir}
}

func (p *WorkspacePermissionsProbe) Name() string   { return "workspace_permissions" }
func (p *WorkspacePermissionsProbe) Target() string { return "system" }

func (p *WorkspacePermissionsProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	if err := os.MkdirAll(p.workspaceDir, 0750); err != nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("failed to access workspace directory %s", p.workspaceDir),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	testFile := filepath.Join(p.workspaceDir, fmt.Sprintf("kelvin-probe-%d.tmp", time.Now().UnixNano()))
	if err := os.WriteFile(testFile, []byte("ready"), 0600); err != nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("workspace directory %s is not writable", p.workspaceDir),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}
	_ = os.Remove(testFile)

	return ProbeResult{
		Name:      p.Name(),
		Target:    p.Target(),
		Status:    StatusReady,
		Message:   fmt.Sprintf("workspace directory %s is writable", p.workspaceDir),
		CheckedAt: start,
		Duration:  time.Since(start),
		Diagnostics: map[string]string{
			"workspace_dir": p.workspaceDir,
		},
	}
}

// ScannerAdapterProbe evaluates the health and runtime version of a registered ScannerAdapter.
type ScannerAdapterProbe struct {
	scannerID     string
	adapter       adapters.ScannerAdapter
	versionPolicy adapters.VersionPolicy
}

func NewScannerAdapterProbe(scannerID string, adapter adapters.ScannerAdapter, policy adapters.VersionPolicy) *ScannerAdapterProbe {
	return &ScannerAdapterProbe{
		scannerID:     scannerID,
		adapter:       adapter,
		versionPolicy: policy,
	}
}

func (p *ScannerAdapterProbe) Name() string   { return p.scannerID + "_adapter" }
func (p *ScannerAdapterProbe) Target() string { return p.scannerID }

func (p *ScannerAdapterProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	if p.adapter == nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("adapter for scanner %s is not registered", p.scannerID),
			Error:     "nil adapter",
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	if err := p.adapter.Health(ctx); err != nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("adapter health check failed for %s", p.scannerID),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	runtimeInfo, err := p.adapter.VerifyRuntimeVersion(ctx)
	if err != nil {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("runtime version verification failed for %s", p.scannerID),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	if p.versionPolicy.ScannerVersion != "" && runtimeInfo.ScannerVersion != p.versionPolicy.ScannerVersion {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("version mismatch for %s: expected %s, got %s", p.scannerID, p.versionPolicy.ScannerVersion, runtimeInfo.ScannerVersion),
			Error:     "version policy violation",
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	return ProbeResult{
		Name:      p.Name(),
		Target:    p.Target(),
		Status:    StatusReady,
		Message:   fmt.Sprintf("scanner adapter %s (v%s) is operational", p.scannerID, runtimeInfo.ScannerVersion),
		CheckedAt: start,
		Duration:  time.Since(start),
		Diagnostics: map[string]string{
			"scanner_version": runtimeInfo.ScannerVersion,
			"adapter_version": runtimeInfo.AdapterVersion,
			"image_ref":       runtimeInfo.ImageReference,
		},
	}
}

// ReleaseManifestProbe checks the authoritative scanner release manifest.
// In staging and production, if the manifest is missing, invalid, or marked "not-released",
// the probe reports StatusUnavailable, keeping the scanner execution plane unavailable.
type ReleaseManifestProbe struct {
	scannerID string
	lockPath  string
	env       string
}

func NewReleaseManifestProbe(scannerID, lockPath, env string) *ReleaseManifestProbe {
	if lockPath == "" {
		lockPath = "deploy/scanners/images.lock.json"
	}
	return &ReleaseManifestProbe{
		scannerID: scannerID,
		lockPath:  lockPath,
		env:       env,
	}
}

func (p *ReleaseManifestProbe) Name() string   { return p.scannerID + "_release_manifest" }
func (p *ReleaseManifestProbe) Target() string { return p.scannerID }

func (p *ReleaseManifestProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	isProdLike := p.env == "staging" || p.env == "production"

	lock, err := manifest.LoadCanonicalLock(p.lockPath)
	if err != nil {
		status := StatusDegraded
		if isProdLike {
			status = StatusUnavailable
		}
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    status,
			Message:   fmt.Sprintf("failed to load release manifest from %s", p.lockPath),
			Error:     err.Error(),
			CheckedAt: start,
			Duration:  time.Since(start),
		}
	}

	if isProdLike && lock.Status != manifest.StatusCertified {
		return ProbeResult{
			Name:      p.Name(),
			Target:    p.Target(),
			Status:    StatusUnavailable,
			Message:   fmt.Sprintf("scanner %s is not certified (manifest status: %s)", p.scannerID, lock.Status),
			Error:     "manifest: scanner is not certified or released for production execution",
			CheckedAt: start,
			Duration:  time.Since(start),
			Diagnostics: map[string]string{
				"status":     lock.Status,
				"lock_path":  p.lockPath,
				"schema_ver": lock.SchemaVersion,
			},
		}
	}

	return ProbeResult{
		Name:      p.Name(),
		Target:    p.Target(),
		Status:    StatusReady,
		Message:   fmt.Sprintf("scanner %s release manifest verified (status: %s)", p.scannerID, lock.Status),
		CheckedAt: start,
		Duration:  time.Since(start),
	}
}

