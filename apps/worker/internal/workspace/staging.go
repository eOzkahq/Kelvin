package workspace

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RetentionPolicy defines the lifecycle rule for raw scanner output artifacts.
type RetentionPolicy string

const (
	// RetentionPurgeAlways purges all raw staged output upon assessment completion.
	RetentionPurgeAlways RetentionPolicy = "PURGE_ALWAYS"

	// RetentionRetainOnFailure purges raw output on successful assessments, but preserves
	// compressed diagnostics when assessments fail or terminate unexpectedly.
	RetentionRetainOnFailure RetentionPolicy = "RETAIN_ON_FAILURE"

	// RetentionRetainAlways preserves compressed raw output for all assessment runs.
	RetentionRetainAlways RetentionPolicy = "RETAIN_ALWAYS"
)

// StagedArtifact represents a temporary, untrusted raw scanner output file in staging.
type StagedArtifact struct {
	ArtifactID   string    `json:"artifact_id"`
	TenantID     string    `json:"tenant_id"`
	AssessmentID string    `json:"assessment_id"`
	RunID        string    `json:"run_id"`
	ScannerID    string    `json:"scanner_id"`
	StreamType   string    `json:"stream_type"` // e.g. "stdout", "stderr", "report", "raw"
	FilePath     string    `json:"file_path"`
	SizeBytes    int64     `json:"size_bytes"`
	SHA256       string    `json:"sha256"`
	Compressed   bool      `json:"compressed"`
	CreatedAt    time.Time `json:"created_at"`
	Purged       bool      `json:"purged"`
}

// CleanupFailureRecord captures diagnostic telemetry for failed cleanup attempts.
type CleanupFailureRecord struct {
	TenantID     string    `json:"tenant_id"`
	AssessmentID string    `json:"assessment_id"`
	RunID        string    `json:"run_id"`
	Path         string    `json:"path"`
	Error        string    `json:"error"`
	OccurredAt   time.Time `json:"occurred_at"`
}

// CleanupObserver receives notifications of workspace cleanup and purge errors.
type CleanupObserver interface {
	RecordCleanupFailure(rec CleanupFailureRecord)
}

// AuditRecorder is a thread-safe in-memory recorder for cleanup failure telemetry.
type AuditRecorder struct {
	mu       sync.Mutex
	failures []CleanupFailureRecord
}

// NewAuditRecorder initializes an empty cleanup failure audit recorder.
func NewAuditRecorder() *AuditRecorder {
	return &AuditRecorder{failures: make([]CleanupFailureRecord, 0)}
}

// RecordCleanupFailure records a cleanup failure.
func (r *AuditRecorder) RecordCleanupFailure(rec CleanupFailureRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, rec)
}

// Failures returns a snapshot copy of all recorded cleanup failures.
func (r *AuditRecorder) Failures() []CleanupFailureRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CleanupFailureRecord, len(r.failures))
	copy(out, r.failures)
	return out
}

// StageRawOutput safely writes untrusted raw scanner output to the workspace staging directory.
func (w *Workspace) StageRawOutput(scannerID, streamType string, content []byte) (*StagedArtifact, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned {
		return nil, ErrWorkspaceCleaned
	}

	sanitizedScanner := strings.ReplaceAll(scannerID, "/", "_")
	sanitizedStream := strings.ReplaceAll(streamType, "/", "_")
	artifactID := uuid.New().String()
	fileName := fmt.Sprintf("%s_%s_%s.raw", sanitizedScanner, sanitizedStream, artifactID[:8])

	targetPath := filepath.Join(w.StagingDir, fileName)
	if err := os.WriteFile(targetPath, content, 0600); err != nil {
		return nil, fmt.Errorf("workspace: stage raw output: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(content)
	digest := hex.EncodeToString(hasher.Sum(nil))

	return &StagedArtifact{
		ArtifactID:   artifactID,
		TenantID:     w.TenantID,
		AssessmentID: w.AssessmentID,
		RunID:        w.RunID,
		ScannerID:    scannerID,
		StreamType:   streamType,
		FilePath:     targetPath,
		SizeBytes:    int64(len(content)),
		SHA256:       digest,
		Compressed:   false,
		CreatedAt:    time.Now().UTC(),
		Purged:       false,
	}, nil
}

// CompressArtifact compresses a staged artifact with gzip, updating its location and metadata.
func (w *Workspace) CompressArtifact(artifact *StagedArtifact) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned {
		return ErrWorkspaceCleaned
	}
	if artifact == nil || artifact.Purged {
		return errors.New("workspace: artifact is nil or already purged")
	}
	if artifact.Compressed {
		return nil
	}

	rawFile, err := os.Open(artifact.FilePath)
	if err != nil {
		return fmt.Errorf("workspace: open raw artifact for compression: %w", err)
	}
	defer rawFile.Close()

	gzPath := artifact.FilePath + ".gz"
	gzFile, err := os.OpenFile(gzPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("workspace: create compressed artifact: %w", err)
	}

	hasher := sha256.New()
	mw := io.MultiWriter(gzFile, hasher)
	gzWriter := gzip.NewWriter(mw)

	var written int64
	buf := make([]byte, 32*1024)
	for {
		n, rErr := rawFile.Read(buf)
		if n > 0 {
			if _, wErr := gzWriter.Write(buf[:n]); wErr != nil {
				_ = gzFile.Close()
				_ = os.Remove(gzPath)
				return fmt.Errorf("workspace: gzip compression error: %w", wErr)
			}
			written += int64(n)
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			_ = gzFile.Close()
			_ = os.Remove(gzPath)
			return fmt.Errorf("workspace: read raw artifact error: %w", rErr)
		}
	}

	if err := gzWriter.Close(); err != nil {
		_ = gzFile.Close()
		_ = os.Remove(gzPath)
		return fmt.Errorf("workspace: close gzip writer: %w", err)
	}
	if err := gzFile.Close(); err != nil {
		_ = os.Remove(gzPath)
		return fmt.Errorf("workspace: close gzip file: %w", err)
	}

	// Remove uncompressed raw file to avoid duplicate storage
	_ = rawFile.Close()
	_ = os.Remove(artifact.FilePath)

	fi, err := os.Stat(gzPath)
	if err != nil {
		return fmt.Errorf("workspace: stat compressed artifact: %w", err)
	}

	artifact.FilePath = gzPath
	artifact.SizeBytes = fi.Size()
	artifact.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	artifact.Compressed = true

	return nil
}

// PurgeArtifact deletes an individual staged artifact from disk.
func (w *Workspace) PurgeArtifact(artifact *StagedArtifact) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if artifact == nil || artifact.Purged {
		return nil
	}

	artifact.Purged = true
	if err := os.Remove(artifact.FilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("workspace: purge artifact %s: %w", artifact.FilePath, err)
	}

	return nil
}

// PurgeStagedOutput removes all files inside the staging directory.
func (w *Workspace) PurgeStagedOutput() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cleaned || w.StagingDir == "" {
		return nil
	}

	entries, err := os.ReadDir(w.StagingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("workspace: read staging directory: %w", err)
	}

	for _, entry := range entries {
		p := filepath.Join(w.StagingDir, entry.Name())
		if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("workspace: remove staged file %s: %w", p, err)
		}
	}

	return nil
}

// ApplyRetentionPolicy manages raw artifacts according to the specified policy.
func (w *Workspace) ApplyRetentionPolicy(policy RetentionPolicy, assessmentSucceeded bool, artifacts []*StagedArtifact) error {
	switch policy {
	case RetentionPurgeAlways:
		return w.PurgeStagedOutput()

	case RetentionRetainOnFailure:
		if assessmentSucceeded {
			return w.PurgeStagedOutput()
		}
		// Failure scenario: compress all uncompressed artifacts for diagnostic retention
		for _, art := range artifacts {
			if !art.Compressed && !art.Purged {
				if err := w.CompressArtifact(art); err != nil {
					return err
				}
			}
		}
		return nil

	case RetentionRetainAlways:
		for _, art := range artifacts {
			if !art.Compressed && !art.Purged {
				if err := w.CompressArtifact(art); err != nil {
					return err
				}
			}
		}
		return nil

	default:
		return w.PurgeStagedOutput()
	}
}

// ReapStaging sweeps all staging directories and removes orphaned artifacts older than maxAge.
func (m *Manager) ReapStaging(ctx context.Context, maxAge time.Duration, observer CleanupObserver) (int, error) {
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
		return 0, fmt.Errorf("workspace: read tenants dir: %w", err)
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
			stagingPath := filepath.Join(runsDir, rEntry.Name(), "staging")
			stagingEntries, err := os.ReadDir(stagingPath)
			if err != nil {
				continue
			}

			for _, sEntry := range stagingEntries {
				filePath := filepath.Join(stagingPath, sEntry.Name())
				info, err := sEntry.Info()
				if err != nil {
					continue
				}

				if info.ModTime().Before(cutoff) {
					if err := os.RemoveAll(filePath); err != nil {
						m.logger.Warn("failed to reap stale staging file",
							zap.String("path", filePath),
							zap.Error(err),
						)
						if observer != nil {
							observer.RecordCleanupFailure(CleanupFailureRecord{
								TenantID:   tEntry.Name(),
								RunID:      rEntry.Name(),
								Path:       filePath,
								Error:      err.Error(),
								OccurredAt: time.Now().UTC(),
							})
						}
					} else {
						reaped++
					}
				}
			}
		}
	}

	return reaped, nil
}
