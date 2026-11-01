package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestWorkspaceCreationAndLayout(t *testing.T) {
	baseDir := t.TempDir()
	mgr, err := NewManager(baseDir, zap.NewNop())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	tenantID := uuid.New().String()
	assessmentID := uuid.New().String()
	runID := uuid.New().String()

	ws, err := mgr.Create(context.Background(), tenantID, assessmentID, runID)
	if err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}
	defer ws.Cleanup()

	// Verify path structure
	expectedRoot := filepath.Join(baseDir, "tenants", tenantID, "runs", runID)
	if ws.RootDir != expectedRoot {
		t.Errorf("expected root %s, got %s", expectedRoot, ws.RootDir)
	}

	for _, sub := range []string{ws.ConfigDir, ws.TmpDir, ws.OutputDir} {
		info, err := os.Stat(sub)
		if err != nil {
			t.Fatalf("subdirectory %s does not exist: %v", sub, err)
		}
		if !info.IsDir() {
			t.Errorf("expected %s to be directory", sub)
		}
	}
}

func TestCrossAssessmentAndTenantIsolation(t *testing.T) {
	baseDir := t.TempDir()
	mgr, err := NewManager(baseDir, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	tenant1 := uuid.New().String()
	tenant2 := uuid.New().String()
	run1 := uuid.New().String()
	run2 := uuid.New().String()

	ws1, err := mgr.Create(context.Background(), tenant1, uuid.New().String(), run1)
	if err != nil {
		t.Fatal(err)
	}
	defer ws1.Cleanup()

	ws2, err := mgr.Create(context.Background(), tenant2, uuid.New().String(), run2)
	if err != nil {
		t.Fatal(err)
	}
	defer ws2.Cleanup()

	// Workspaces must have completely disjoint roots
	if ws1.RootDir == ws2.RootDir {
		t.Fatalf("cross-tenant workspaces shared the same root directory")
	}

	// Writing file in ws1 must not be visible or reachable in ws2
	_, err = ws1.WriteOutputFile("evidence.json", []byte(`{"finding":"x"}`))
	if err != nil {
		t.Fatal(err)
	}

	_, err = ws2.ReadOutputFile("evidence.json")
	if err == nil {
		t.Fatalf("ws2 was able to read file from ws1")
	}
}

func TestPathTraversalPrevention(t *testing.T) {
	baseDir := t.TempDir()
	mgr, err := NewManager(baseDir, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ws, err := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Cleanup()

	traversalPayloads := []string{
		"../escape.txt",
		"..\\escape.txt",
		"sub/../../escape.txt",
		"/etc/passwd",
		"C:\\Windows\\system32\\cmd.exe",
		"file\x00name.txt",
		"file\rname.txt",
		"file\nname.txt",
		"....//....//escape",
	}

	for _, payload := range traversalPayloads {
		_, err := ws.ResolveSafePath("output", payload)
		if err == nil {
			t.Errorf("expected path traversal error for payload %q, got nil", payload)
		}
	}
}

func TestSafeReadWriteOperations(t *testing.T) {
	baseDir := t.TempDir()
	mgr, err := NewManager(baseDir, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ws, err := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Cleanup()

	// Write and read config
	cfgPath, err := ws.WriteConfigFile("nuclei-config.yaml", []byte("rate-limit: 2\n"))
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	if !strings.HasPrefix(cfgPath, ws.ConfigDir) {
		t.Errorf("config path %s not in config dir %s", cfgPath, ws.ConfigDir)
	}

	// Write and read output
	content := []byte(`{"findings":[{"id":"test"}]}`)
	outPath, err := ws.WriteOutputFile("report.json", content)
	if err != nil {
		t.Fatalf("failed to write output file: %v", err)
	}
	if !strings.HasPrefix(outPath, ws.OutputDir) {
		t.Errorf("output path %s not in output dir %s", outPath, ws.OutputDir)
	}

	readBack, err := ws.ReadOutputFile("report.json")
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(readBack) != string(content) {
		t.Errorf("content mismatch: got %s, want %s", string(readBack), string(content))
	}

	// List outputs
	outputs, err := ws.ListOutputs()
	if err != nil {
		t.Fatalf("failed to list outputs: %v", err)
	}
	if len(outputs) != 1 || outputs[0] != "report.json" {
		t.Errorf("unexpected output list: %+v", outputs)
	}
}

func TestCleanupIdempotenceAndLifecycle(t *testing.T) {
	baseDir := t.TempDir()
	mgr, err := NewManager(baseDir, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ws, err := mgr.Create(context.Background(), uuid.New().String(), uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}

	root := ws.RootDir
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("root dir %s does not exist: %v", root, err)
	}

	// Cleanup on success/failure/cancellation
	if err := ws.Cleanup(); err != nil {
		t.Fatalf("first cleanup failed: %v", err)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("expected root dir to be deleted, still exists")
	}

	// Second cleanup should be a no-op
	if err := ws.Cleanup(); err != nil {
		t.Fatalf("second cleanup failed: %v", err)
	}

	// Access after cleanup should fail
	if _, err := ws.ResolveSafePath("output", "test.txt"); err != ErrWorkspaceCleaned {
		t.Errorf("expected ErrWorkspaceCleaned, got %v", err)
	}
}

func TestReapStaleWorkspaces(t *testing.T) {
	baseDir := t.TempDir()
	mgr, err := NewManager(baseDir, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	tenantID := uuid.New().String()
	ws1, err := mgr.Create(context.Background(), tenantID, uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ws1.Cleanup()

	ws2, err := mgr.Create(context.Background(), tenantID, uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ws2.Cleanup()

	// Artificially age ws1 by setting its mod time back 2 hours
	oldTime := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(ws1.RootDir, oldTime, oldTime)

	// Reap workspaces older than 1 hour
	reaped, err := mgr.ReapStale(context.Background(), 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to reap stale workspaces: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("expected 1 reaped workspace, got %d", reaped)
	}

	// ws1 should be removed, ws2 should remain
	if _, err := os.Stat(ws1.RootDir); !os.IsNotExist(err) {
		t.Errorf("expected ws1 to be deleted")
	}
	if _, err := os.Stat(ws2.RootDir); os.IsNotExist(err) {
		t.Errorf("expected ws2 to still exist")
	}
}
