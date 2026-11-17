package reaper

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/workspace"
	"go.uber.org/zap"
)

// ContainerRuntime defines operations for inspecting and terminating scanner containers.
type ContainerRuntime interface {
	ListContainers(ctx context.Context, filter string) ([]ContainerInfo, error)
	RemoveContainer(ctx context.Context, idOrName string, force bool) error
}

// ContainerInfo describes a container queried from the container engine.
type ContainerInfo struct {
	ID        string            `json:"Id"`
	Names     []string          `json:"Names"`
	Image     string            `json:"Image"`
	Created   int64             `json:"Created"`
	CreatedAt string            `json:"CreatedAt"`
	State     string            `json:"State"`
	Labels    map[string]string `json:"Labels"`
}

// PodmanRuntime interacts with rootless Podman via the CLI.
type PodmanRuntime struct {
	executable string
}

func NewPodmanRuntime(executable string) *PodmanRuntime {
	if executable == "" {
		executable = "podman"
	}
	return &PodmanRuntime{executable: executable}
}

func (p *PodmanRuntime) ListContainers(ctx context.Context, filter string) ([]ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	args := []string{"ps", "-a", "--format", "json"}
	if filter != "" {
		args = append(args, "--filter", filter)
	}

	cmd := exec.CommandContext(ctx, p.executable, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reaper: list containers failed: %w", err)
	}

	if len(out) == 0 {
		return nil, nil
	}

	var containers []ContainerInfo
	if err := json.Unmarshal(out, &containers); err != nil {
		// In some podman versions, single container output is a JSON object instead of array
		var single ContainerInfo
		if errSingle := json.Unmarshal(out, &single); errSingle == nil {
			return []ContainerInfo{single}, nil
		}
		return nil, fmt.Errorf("reaper: parse container list json: %w", err)
	}

	return containers, nil
}

func (p *PodmanRuntime) RemoveContainer(ctx context.Context, idOrName string, force bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	args := []string{"rm"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, idOrName)

	cmd := exec.CommandContext(ctx, p.executable, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reaper: remove container %q failed: %w (output: %s)", idOrName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// OrphanContainerReaper identifies and eliminates abandoned or leaked scanner containers.
type OrphanContainerReaper struct {
	runtime ContainerRuntime
	logger  *zap.Logger
	maxAge  time.Duration
	prefix  string
}

func NewOrphanContainerReaper(runtime ContainerRuntime, maxAge time.Duration, logger *zap.Logger) *OrphanContainerReaper {
	if maxAge <= 0 {
		maxAge = 30 * time.Minute
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &OrphanContainerReaper{
		runtime: runtime,
		logger:  logger.With(zap.String("component", "orphan_container_reaper")),
		maxAge:  maxAge,
		prefix:  "kelvin-job-",
	}
}

// ReapOrphans scans for and forcibly removes orphaned scanner containers.
func (r *OrphanContainerReaper) ReapOrphans(ctx context.Context) (int, error) {
	containers, err := r.runtime.ListContainers(ctx, "")
	if err != nil {
		return 0, err
	}

	reaped := 0
	cutoff := time.Now().Add(-r.maxAge)

	for _, c := range containers {
		isKelvinScanner := false
		for _, name := range c.Names {
			trimmedName := strings.TrimPrefix(name, "/")
			if strings.HasPrefix(trimmedName, r.prefix) {
				isKelvinScanner = true
				break
			}
		}

		if !isKelvinScanner {
			continue
		}

		stateLower := strings.ToLower(c.State)
		shouldReap := false
		reason := ""

		// 1. Any exited, dead, or stopped container was abandoned and not cleaned
		if stateLower == "exited" || stateLower == "dead" || stateLower == "stopped" {
			shouldReap = true
			reason = fmt.Sprintf("container in stopped state %q", c.State)
		} else {
			// 2. Check container age for running or stalled containers
			var createdTime time.Time
			if c.Created > 0 {
				createdTime = time.Unix(c.Created, 0)
			} else if c.CreatedAt != "" {
				t, err := time.Parse(time.RFC3339Nano, c.CreatedAt)
				if err == nil {
					createdTime = t
				} else if t2, err2 := time.Parse(time.RFC3339, c.CreatedAt); err2 == nil {
					createdTime = t2
				}
			}

			if !createdTime.IsZero() && createdTime.Before(cutoff) {
				shouldReap = true
				reason = fmt.Sprintf("container exceeded max lifetime (%s > %s)", time.Since(createdTime), r.maxAge)
			}
		}

		if shouldReap {
			containerTarget := c.ID
			if len(c.Names) > 0 {
				containerTarget = c.Names[0]
			}
			r.logger.Warn("reaping orphaned container",
				zap.String("container", containerTarget),
				zap.String("reason", reason),
				zap.String("state", c.State),
			)
			if err := r.runtime.RemoveContainer(ctx, containerTarget, true); err != nil {
				r.logger.Error("failed to remove orphan container",
					zap.String("container", containerTarget),
					zap.Error(err),
				)
			} else {
				reaped++
			}
		}
	}

	if reaped > 0 {
		r.logger.Info("reaped orphaned scanner containers", zap.Int("count", reaped))
	}
	return reaped, nil
}

// CompositeReaper coordinates database, container, and filesystem workspace sweeps.
type CompositeReaper struct {
	Store            storeIface
	ContainerReaper  *OrphanContainerReaper
	WorkspaceManager *workspace.Manager
	WorkspaceMaxAge  time.Duration
	Interval         time.Duration
	Logger           *zap.Logger
}

func NewCompositeReaper(
	store storeIface,
	runtime ContainerRuntime,
	wsManager *workspace.Manager,
	interval time.Duration,
	maxAge time.Duration,
	logger *zap.Logger,
) *CompositeReaper {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if maxAge <= 0 {
		maxAge = 30 * time.Minute
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	var cr *OrphanContainerReaper
	if runtime != nil {
		cr = NewOrphanContainerReaper(runtime, maxAge, logger)
	}

	return &CompositeReaper{
		Store:            store,
		ContainerReaper:  cr,
		WorkspaceManager: wsManager,
		WorkspaceMaxAge:  maxAge,
		Interval:         interval,
		Logger:           logger.With(zap.String("component", "composite_reaper")),
	}
}

// ReapOnce executes a single sweep across all configured subsystems.
func (c *CompositeReaper) ReapOnce(ctx context.Context) error {
	var errs []string

	// 1. Stalled DB jobs
	if c.Store != nil {
		if err := reapOnce(ctx, c.Logger, c.Store); err != nil {
			errs = append(errs, fmt.Sprintf("store: %v", err))
		}
	}

	// 2. Orphaned containers
	if c.ContainerReaper != nil {
		if _, err := c.ContainerReaper.ReapOrphans(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("containers: %v", err))
		}
	}

	// 3. Stale workspaces
	if c.WorkspaceManager != nil {
		reapedWs, err := c.WorkspaceManager.ReapStale(ctx, c.WorkspaceMaxAge)
		if err != nil {
			errs = append(errs, fmt.Sprintf("workspaces: %v", err))
		} else if reapedWs > 0 {
			c.Logger.Info("reaped stale workspaces", zap.Int("count", reapedWs))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("reaper: partial sweep failure: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Run blocks until ctx is cancelled, executing sweeps on each tick.
func (c *CompositeReaper) Run(ctx context.Context) error {
	c.Logger.Info("composite reaper started",
		zap.Duration("interval", c.Interval),
		zap.Duration("max_age", c.WorkspaceMaxAge),
	)

	// Immediate startup sweep
	_ = c.ReapOnce(ctx)

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.Logger.Info("composite reaper stopped")
			return nil
		case <-ticker.C:
			_ = c.ReapOnce(ctx)
		}
	}
}
