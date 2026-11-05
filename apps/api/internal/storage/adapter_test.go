package storage

import (
	"context"
	"testing"
)

func TestEvidenceStorageAdapter(t *testing.T) {
	ctx := context.Background()
	memStorage := NewMemoryStorageProvider("secret")
	adapter := NewEvidenceStorageAdapter(memStorage, "kelvin-evidence-private")

	tenantID := "tenant-test"
	objectID := "assessment-99/evidence-raw.json"
	data := []byte(`{"scan_id":"99","status":"done"}`)

	// PutObject
	meta, err := adapter.PutObject(ctx, tenantID, objectID, "application/json", data)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if meta.TenantID != tenantID || meta.ObjectID != objectID {
		t.Errorf("metadata mismatch: %+v", meta)
	}

	// GetObject
	retrieved, getMeta, err := adapter.GetObject(ctx, tenantID, objectID)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if string(retrieved) != string(data) {
		t.Errorf("data mismatch: expected %s, got %s", string(data), string(retrieved))
	}
	if getMeta.SizeBytes != int64(len(data)) {
		t.Errorf("size mismatch: %d vs %d", getMeta.SizeBytes, len(data))
	}

	// GetMetadata
	statMeta, err := adapter.GetMetadata(ctx, tenantID, objectID)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if statMeta.SizeBytes != int64(len(data)) {
		t.Errorf("metadata size mismatch: %d", statMeta.SizeBytes)
	}

	// SecurePurge
	if err := adapter.SecurePurge(ctx, tenantID, objectID); err != nil {
		t.Fatalf("SecurePurge failed: %v", err)
	}

	// Verify gone
	_, _, err = adapter.GetObject(ctx, tenantID, objectID)
	if err == nil {
		t.Fatalf("expected error after SecurePurge, got nil")
	}
}

func TestReportingObjectStoreAdapter(t *testing.T) {
	ctx := context.Background()
	memStorage := NewMemoryStorageProvider("secret")
	adapter := NewReportingObjectStoreAdapter(memStorage, "kelvin-reports-private")

	reportPath := "tenant-test/assessment-88/executive-summary.pdf"
	pdfContent := []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj")

	if err := adapter.Put(ctx, reportPath, pdfContent); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := adapter.Get(ctx, reportPath)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got) != string(pdfContent) {
		t.Errorf("content mismatch")
	}

	if err := adapter.Delete(ctx, reportPath); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = adapter.Get(ctx, reportPath)
	if err == nil {
		t.Fatalf("expected error after Delete, got nil")
	}
}
