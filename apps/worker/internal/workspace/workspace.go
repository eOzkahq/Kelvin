package workspace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrPathTraversal    = errors.New("workspace: path traversal detected")
	ErrInvalidIdentifier = errors.New("workspace: invalid identifier")
	ErrWorkspaceCleaned = errors.New("workspace: workspace has already been cleaned up")
)

// Workspace represents an isolated, temporary filesystem workspace for a single assessment execution.
type Workspace struct {
	TenantID     string    `json:"tenant_id"`
	AssessmentID string    `json:"assessment_id"`
	RunID        string    `json:"run_id"`
	RootDir      string    `json:"root_dir"`
	ConfigDir    string    `json:"config_dir"`
	TmpDir       string    `json:"tmp_dir"`
	OutputDir    string    `json:"output_dir"`
	CreatedAt    time.Time `json:"created_at"`

	mu      sync.Mutex
	cleaned bool
}

// ResolveSafePath ensures that a target file path strictly resides within the designated
// workspace subdirectory ("config", "tmp", "output", or ""), preventing path traversal attacks.
func (w *Workspace) ResolveSafePath(subDir string, relativePath string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned {
		return "", ErrWorkspaceCleaned
	}

	if strings.ContainsAny(relativePath, "\x00\r\n") {
		return "", fmt.Errorf("%w: path contains control characters", ErrPathTraversal)
	}

	var baseDir string
	switch subDir {
	case "config":
		baseDir = w.ConfigDir
	case "tmp":
		baseDir = w.TmpDir
	case "output":
		baseDir = w.OutputDir
	case "":
		baseDir = w.RootDir
	default:
		return "", fmt.Errorf("workspace: invalid subdirectory %q", subDir)
	}

	// Reject absolute or drive-rooted paths supplied as relative input
	if filepath.IsAbs(relativePath) || strings.HasPrefix(relativePath, "/") || strings.HasPrefix(relativePath, "\\") || strings.Contains(relativePath, ":") {
		return "", fmt.Errorf("%w: absolute or rooted paths are not permitted", ErrPathTraversal)
	}

	cleanedRel := filepath.Clean(relativePath)
	if strings.HasPrefix(cleanedRel, "..") || cleanedRel == "." && relativePath != "." {
		return "", fmt.Errorf("%w: path escapes workspace boundaries", ErrPathTraversal)
	}

	targetPath := filepath.Join(baseDir, cleanedRel)
	cleanTarget := filepath.Clean(targetPath)
	cleanBase := filepath.Clean(baseDir)

	if !strings.HasPrefix(cleanTarget, cleanBase+string(filepath.Separator)) && cleanTarget != cleanBase {
		return "", fmt.Errorf("%w: path escapes workspace base directory", ErrPathTraversal)
	}

	return cleanTarget, nil
}

// WriteConfigFile safely writes a scanner configuration file into the workspace config directory.
func (w *Workspace) WriteConfigFile(name string, content []byte) (string, error) {
	path, err := w.ResolveSafePath("config", name)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("workspace: create config parent directory: %w", err)
	}

	if err := os.WriteFile(path, content, 0600); err != nil {
		return "", fmt.Errorf("workspace: write config file: %w", err)
	}

	return path, nil
}

// WriteOutputFile safely writes a raw artifact or finding into the workspace output directory.
func (w *Workspace) WriteOutputFile(name string, content []byte) (string, error) {
	path, err := w.ResolveSafePath("output", name)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("workspace: create output parent directory: %w", err)
	}

	if err := os.WriteFile(path, content, 0600); err != nil {
		return "", fmt.Errorf("workspace: write output file: %w", err)
	}

	return path, nil
}

// ReadOutputFile safely reads an output artifact from the workspace output directory.
func (w *Workspace) ReadOutputFile(name string) ([]byte, error) {
	path, err := w.ResolveSafePath("output", name)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path)
}

// ListOutputs returns relative paths of all files in the output directory.
func (w *Workspace) ListOutputs() ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned {
		return nil, ErrWorkspaceCleaned
	}

	var files []string
	err := filepath.Walk(w.OutputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, err := filepath.Rel(w.OutputDir, path)
			if err == nil {
				files = append(files, rel)
			}
		}
		return nil
	})

	return files, err
}

// Cleanup securely shreds and removes all files and directories in the workspace.
// Cleanup is idempotent and safe to call multiple times.
func (w *Workspace) Cleanup() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned {
		return nil
	}

	w.cleaned = true
	if w.RootDir == "" {
		return nil
	}

	return os.RemoveAll(w.RootDir)
}

// Manager coordinates the creation, isolation, and lifecycle cleanup of per-assessment workspaces.
type Manager struct {
	baseDir string
	logger  *zap.Logger
}

func NewManager(baseDir string, logger *zap.Logger) (*Manager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "kelvin", "workspaces")
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("workspace: initialize base directory %s: %w", baseDir, err)
	}

	return &Manager{
		baseDir: baseDir,
		logger:  logger,
	}, nil
}

// Create establishes a dedicated, isolated workspace with controlled permissions for an assessment execution.
func (m *Manager) Create(ctx context.Context, tenantID, assessmentID, runID string) (*Workspace, error) {
	if err := validateID(tenantID, "tenant_id"); err != nil {
		return nil, err
	}
	if err := validateID(assessmentID, "assessment_id"); err != nil {
		return nil, err
	}
	if err := validateID(runID, "run_id"); err != nil {
		return nil, err
	}

	// Isolated path layout: <baseDir>/tenants/<tenantID>/runs/<runID>
	rootDir := filepath.Join(m.baseDir, "tenants", tenantID, "runs", runID)
	configDir := filepath.Join(rootDir, "config")
	tmpDir := filepath.Join(rootDir, "tmp")
	outputDir := filepath.Join(rootDir, "output")

	for _, dir := range []string{configDir, tmpDir, outputDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			_ = os.RemoveAll(rootDir)
			return nil, fmt.Errorf("workspace: create directory %s: %w", dir, err)
		}
	}

	ws := &Workspace{
		TenantID:     tenantID,
		AssessmentID: assessmentID,
		RunID:        runID,
		RootDir:      rootDir,
		ConfigDir:    configDir,
		TmpDir:       tmpDir,
		OutputDir:    outputDir,
		CreatedAt:    time.Now().UTC(),
	}

	m.logger.Debug("workspace created",
		zap.String("tenant_id", tenantID),
		zap.String("assessment_id", assessmentID),
		zap.String("run_id", runID),
		zap.String("root_dir", rootDir),
	)

	return ws, nil
}

// ReapStale sweeps the workspace base directory and removes orphaned or stale workspaces
// older than maxAge that were left behind by interrupted executions or killed worker processes.
func (m *Manager) ReapStale(ctx context.Context, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		maxAge = 1 * time.Hour
	}

	cutoff := time.Now().Add(-maxAge)
	tenantsDir := filepath.Join(m.baseDir, "tenants")
	if _, err := os.Stat(tenantsDir); os.IsNotExist(err) {
		return 0, nil
	}

	reaped := 0
	tenantEntries, err := os.ReadDir(tenantsDir)
	if err != nil {
		return 0, fmt.Errorf("workspace: read tenants directory: %w", err)
	}

	for _, tEntry := range tenantEntries {
		if !tEntry.IsDir() {
			continue
		}
		runsDir := filepath.Join(tenantsDir, tEntry.Name(), "runs")
		runEntries, err := os.ReadDir(runsDir)
		if err != nil {
			continue
		}

		for _, rEntry := range runEntries {
			if !rEntry.IsDir() {
				continue
			}
			runPath := filepath.Join(runsDir, rEntry.Name())
			info, err := rEntry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().Before(cutoff) {
				if err := os.RemoveAll(runPath); err == nil {
					reaped++
					m.logger.Info("reaped stale workspace",
						zap.String("path", runPath),
						zap.Time("mod_time", info.ModTime()),
					)
				}
			}
		}

		// Clean up empty tenant directory if all runs were reaped
		remainingRuns, _ := os.ReadDir(runsDir)
		if len(remainingRuns) == 0 {
			_ = os.Remove(runsDir)
			_ = os.Remove(filepath.Join(tenantsDir, tEntry.Name()))
		}
	}

	return reaped, nil
}

func validateID(id, name string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidIdentifier, name)
	}
	if _, err := uuid.Parse(id); err == nil {
		return nil
	}
	// Fallback to strict alphanumeric with hyphen for non-UUID test IDs
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return fmt.Errorf("%w: %s contains invalid character %q", ErrInvalidIdentifier, name, r)
		}
	}
	return nil
}
