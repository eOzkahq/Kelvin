// Package runner orchestrates secure, certified container execution for the Kelvin worker.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
	"go.uber.org/zap"
)

var (
	ErrCertificationFailed   = errors.New("runner: scanner certification gate failed")
	ErrDockerSocketForbidden = errors.New("runner: Docker socket access is strictly prohibited by ADR-0008")
	ErrRootlessRequired      = errors.New("runner: unprivileged rootless Podman execution is required")
)

// PodmanRunner manages secure, rootless Podman execution of certified scanner containers.
type PodmanRunner struct {
	manifestPath string
	environment  string
	executor     sandbox.Executor
	logger       *zap.Logger
}

// NewPodmanRunner constructs a PodmanRunner with fail-closed release certification gating.
func NewPodmanRunner(manifestPath, env string, executor sandbox.Executor, logger *zap.Logger) *PodmanRunner {
	if logger == nil {
		logger = zap.NewNop()
	}
	if strings.TrimSpace(manifestPath) == "" {
		manifestPath = "deploy/scanners/images.lock.json"
	}
	return &PodmanRunner{
		manifestPath: manifestPath,
		environment:  env,
		executor:     executor,
		logger:       logger,
	}
}

// VerifyCertification checks whether the target scanner image is officially certified
// in images.lock.json, rejecting unreleased, uncertified, or tampered images.
func (p *PodmanRunner) VerifyCertification(scannerID, imageRef string) error {
	err := manifest.VerifyScannerCertificationForExecution(p.manifestPath, scannerID, imageRef, p.environment)
	if err != nil {
		p.logger.Error("SECURITY_AUDIT: scanner certification verification failed",
			zap.String("event", "scanner_certification_blocked"),
			zap.String("scanner", scannerID),
			zap.String("image_ref", imageRef),
			zap.String("environment", p.environment),
			zap.Error(err),
		)
		return fmt.Errorf("%w: %w", ErrCertificationFailed, err)
	}
	p.logger.Info("SECURITY_AUDIT: scanner certification confirmed",
		zap.String("event", "scanner_certification_verified"),
		zap.String("scanner", scannerID),
		zap.String("image_ref", imageRef),
		zap.String("environment", p.environment),
	)
	return nil
}

// VerifyRootlessRuntime ensures that the runtime environment is rootless Podman
// and strictly forbids Docker daemon/socket execution.
func (p *PodmanRunner) VerifyRootlessRuntime(ctx context.Context, ociExec *sandbox.OCIExecutor) error {
	// Check for forbidden Docker socket environment
	if dockerHost := os.Getenv("DOCKER_HOST"); dockerHost != "" {
		p.logger.Error("SECURITY_AUDIT: Docker daemon socket access attempted",
			zap.String("event", "docker_socket_forbidden"),
			zap.String("docker_host", dockerHost),
		)
		return fmt.Errorf("%w: DOCKER_HOST=%q is forbidden", ErrDockerSocketForbidden, dockerHost)
	}

	if ociExec == nil {
		return nil
	}

	if err := ociExec.VerifyRootlessPodman(ctx); err != nil {
		p.logger.Error("SECURITY_AUDIT: rootless Podman verification failed",
			zap.String("event", "rootless_runtime_failure"),
			zap.Error(err),
		)
		return fmt.Errorf("%w: %w", ErrRootlessRequired, err)
	}

	return nil
}

// Execute enforces certification and runtime hardening gates prior to container launch.
func (p *PodmanRunner) Execute(ctx context.Context, spec sandbox.Spec, ociExec *sandbox.OCIExecutor) (*sandbox.Result, error) {
	scannerID := spec.ScannerID()

	// Gate 1: Enforce scanner certification before execution
	if err := p.VerifyCertification(scannerID, spec.Image); err != nil {
		return nil, err
	}

	// Gate 2: Enforce rootless Podman execution & prohibit Docker socket
	if err := p.VerifyRootlessRuntime(ctx, ociExec); err != nil {
		return nil, err
	}

	// Gate 3: Execute in isolated sandbox
	p.logger.Info("SECURITY_AUDIT: launching certified scanner container",
		zap.String("event", "scanner_container_launch"),
		zap.String("scanner", scannerID),
		zap.String("image", spec.Image),
	)

	result, err := p.executor.Execute(ctx, spec)
	if err != nil {
		p.logger.Error("SECURITY_AUDIT: scanner container execution failed",
			zap.String("event", "scanner_container_failed"),
			zap.String("scanner", scannerID),
			zap.Error(err),
		)
		return result, err
	}

	p.logger.Info("SECURITY_AUDIT: scanner container execution completed",
		zap.String("event", "scanner_container_completed"),
		zap.String("scanner", scannerID),
		zap.String("container", result.ContainerName),
		zap.Int("exit_code", result.ExitCode),
	)

	return result, nil
}
