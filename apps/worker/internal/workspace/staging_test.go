package workspace_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/workspace"
	"go.uber.org/zap"
)

func TestWorkspaceStageRawOutput(t *testing.T) {
	mgr, err := workspace.NewManager(t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	tenantID := uuid.New().String()
	assessmentID := uuid.New().String()
	runID := uuid.New().String()

	ws, err := mgr.Create(context.Background(), tenantID, assessmentID, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Cleanup()

	payload := []byte("scanner raw stdout: target scanned")
	art, err := ws.StageRawOutput("nuclei", "stdout", payload)
	if err != nil {
		t.Fatalf("unexpected stage error: %v", err)
	}

	if art.TenantID != tenantID || art.AssessmentID != assessmentID || art.RunID != runID {
		t.Fatalf("unexpected metadata in staged artifact: %+v", art)
	}
	if art.ScannerID != "nuclei" || art.StreamType != "stdout" {
		t.Fatalf("unexpected scanner/stream: %+v", art)
	}
	if art.SizeBytes != int64(len(payload)) {
		t.Fatalf("expected size %d, got %d", len(payload), art.SizeBytes)
	}
	if art.Compressed {
		t.Fatalf("artifact should not be marked compressed initially")
	}

	readBytes, err := os.ReadFile(art.FilePath)
	if err != nil {
		t.Fatalf("failed to read staged file: %v", err)
	}
	if !bytes.Equal(readBytes, payload) {
		t.Fatalf("staged content mismatch: got %q, expected %q", readBytes, payload)
	}
}

func TestWorkspaceCompressStagedArtifact(t *testing.T) {
	mgr, err := workspace.NewManager(t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ws, err := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Cleanup()

	payload := bytes.Repeat([]byte("repeating text for compression testing "), 100)
	art, err := ws.StageRawOutput("zap", "report", payload)
	if err != nil {
		t.Fatal(err)
	}

	rawPath := art.FilePath
	if err := ws.CompressArtifact(art); err != nil {
		t.Fatalf("compression failed: %v", err)
	}

	if !art.Compressed {
		t.Fatalf("expected artifact.Compressed = true")
	}
	if !filepath.IsAbs(art.FilePath) || filepath.Ext(art.FilePath) != ".gz" {
		t.Fatalf("expected .gz extension, got: %s", art.FilePath)
	}
	// Verify raw uncompressed file was removed
	if _, err := os.Stat(rawPath); !os.IsNotExist(err) {
		t.Fatalf("expected raw file to be removed after compression")
	}

	// Decompress and verify content
	gzFile, err := os.Open(art.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer gzFile.Close()

	zr, err := gzip.NewReader(gzFile)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Fatalf("decompressed data mismatch")
	}
}

func TestWorkspaceApplyRetentionPolicy(t *testing.T) {
	t.Run("PurgeAlways", func(t *testing.T) {
		mgr, _ := workspace.NewManager(t.TempDir(), zap.NewNop())
		ws, _ := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
		defer ws.Cleanup()

		art, _ := ws.StageRawOutput("nuclei", "stdout", []byte("raw data"))
		if err := ws.ApplyRetentionPolicy(workspace.RetentionPurgeAlways, true, []*workspace.StagedArtifact{art}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(art.FilePath); !os.IsNotExist(err) {
			t.Fatalf("expected staged file to be purged under RetentionPurgeAlways")
		}
	})

	t.Run("RetainOnFailure_Success", func(t *testing.T) {
		mgr, _ := workspace.NewManager(t.TempDir(), zap.NewNop())
		ws, _ := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
		defer ws.Cleanup()

		art, _ := ws.StageRawOutput("nuclei", "stdout", []byte("raw data"))
		if err := ws.ApplyRetentionPolicy(workspace.RetentionRetainOnFailure, true, []*workspace.StagedArtifact{art}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(art.FilePath); !os.IsNotExist(err) {
			t.Fatalf("expected staged file to be purged on success under RetentionRetainOnFailure")
		}
	})

	t.Run("RetainOnFailure_Failure", func(t *testing.T) {
		mgr, _ := workspace.NewManager(t.TempDir(), zap.NewNop())
		ws, _ := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
		defer ws.Cleanup()

		art, _ := ws.StageRawOutput("nuclei", "stdout", []byte("raw diagnostic data"))
		if err := ws.ApplyRetentionPolicy(workspace.RetentionRetainOnFailure, false, []*workspace.StagedArtifact{art}); err != nil {
			t.Fatal(err)
		}
		if !art.Compressed {
			t.Fatalf("expected staged file to be compressed for evidence under failure")
		}
		if _, err := os.Stat(art.FilePath); err != nil {
			t.Fatalf("expected compressed evidence file to be preserved on failure")
		}
	})
}

func TestManagerReapStaging(t *testing.T) {
	tempBase := t.TempDir()
	mgr, _ := workspace.NewManager(tempBase, zap.NewNop())

	tenantID := uuid.New().String()
	runID := uuid.New().String()
	ws, _ := mgr.Create(context.Background(), tenantID, uuid.New().String(), runID)

	art, _ := ws.StageRawOutput("nuclei", "stdout", []byte("interrupted execution data"))

	// Backdate the staging file to simulate an orphaned/abandoned execution
	oldTime := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(art.FilePath, oldTime, oldTime)

	audit := workspace.NewAuditRecorder()
	reaped, err := mgr.ReapStaging(context.Background(), 1*time.Hour, audit)
	if err != nil {
		t.Fatalf("unexpected reap error: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("expected 1 stale staging file reaped, got %d", reaped)
	}

	if _, err := os.Stat(art.FilePath); !os.IsNotExist(err) {
		t.Fatalf("expected stale staging file to be deleted")
	}
	if len(audit.Failures()) != 0 {
		t.Fatalf("expected 0 cleanup failures in audit, got %d", len(audit.Failures()))
	}
}

func TestAuditRecorderRecordsFailures(t *testing.T) {
	audit := workspace.NewAuditRecorder()
	audit.RecordCleanupFailure(workspace.CleanupFailureRecord{
		TenantID:     "t-1",
		AssessmentID: "a-1",
		RunID:        "r-1",
		Path:         "/tmp/test",
		Error:        "permission denied",
		OccurredAt:   time.Now().UTC(),
	})

	failures := audit.Failures()
	if len(failures) != 1 {
		t.Fatalf("expected 1 recorded failure, got %d", len(failures))
	}
	if failures[0].TenantID != "t-1" || failures[0].Error != "permission denied" {
		t.Fatalf("unexpected failure record content: %+v", failures[0])
	}
}
