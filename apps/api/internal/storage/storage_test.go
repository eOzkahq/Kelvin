package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateStoragePath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		tenantID    string
		expectError error
	}{
		{
			name:        "valid 3-segment path",
			path:        "tenant-alpha/assessment-001/evidence.json",
			tenantID:    "tenant-alpha",
			expectError: nil,
		},
		{
			name:        "valid deep path",
			path:        "/tenant-alpha/assessment-001/logs/run-1.txt",
			tenantID:    "tenant-alpha",
			expectError: nil,
		},
		{
			name:        "cross tenant access rejected",
			path:        "tenant-beta/assessment-001/evidence.json",
			tenantID:    "tenant-alpha",
			expectError: ErrCrossTenantAccess,
		},
		{
			name:        "insufficient path hierarchy rejected",
			path:        "tenant-alpha/evidence.json",
			tenantID:    "tenant-alpha",
			expectError: ErrInvalidStoragePath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStoragePath(tt.path, tt.tenantID)
			if tt.expectError != nil {
				if err == nil || !errors.Is(err, tt.expectError) {
					t.Fatalf("expected error %v, got %v", tt.expectError, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateArtifact(t *testing.T) {
	// Size limit test
	largePayload := make([]byte, MaxArtifactSizeBytes+1)
	if err := ValidateArtifact("application/json", largePayload); !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("expected ErrFileTooLarge, got %v", err)
	}

	// Unauthorized content type
	if err := ValidateArtifact("application/x-executable", []byte("MZ...")); !errors.Is(err, ErrInvalidContentType) {
		t.Errorf("expected ErrInvalidContentType, got %v", err)
	}

	// Valid PDF
	pdfData := []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj")
	if err := ValidateArtifact("application/pdf", pdfData); err != nil {
		t.Errorf("expected valid PDF to pass, got %v", err)
	}

	// Corrupted PDF (missing %PDF- header)
	badPdfData := []byte("Not a real PDF header")
	if err := ValidateArtifact("application/pdf", badPdfData); !errors.Is(err, ErrCorruptedPayload) {
		t.Errorf("expected ErrCorruptedPayload for bad PDF, got %v", err)
	}

	// Valid JSON
	jsonData := []byte(`{"status":"ok","score":95}`)
	if err := ValidateArtifact("application/json", jsonData); err != nil {
		t.Errorf("expected valid JSON to pass, got %v", err)
	}

	// Corrupted JSON
	badJsonData := []byte(`{"status":"incomplete"`)
	if err := ValidateArtifact("application/json", badJsonData); !errors.Is(err, ErrCorruptedPayload) {
		t.Errorf("expected ErrCorruptedPayload for bad JSON, got %v", err)
	}
}

func TestMemoryStorageProviderLifecycle(t *testing.T) {
	ctx := context.Background()
	provider := NewMemoryStorageProvider("secret-test-key")

	bucket := "kelvin-evidence-private"
	objectPath := "tenant-alpha/assessment-100/scan-trace.json"
	payload := []byte(`{"vulnerabilities":[],"summary":"passed"}`)

	// 1. Upload
	err := provider.Upload(ctx, bucket, objectPath, "application/json", payload)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// 2. Download
	downloaded, err := provider.Download(ctx, bucket, objectPath)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if string(downloaded) != string(payload) {
		t.Errorf("expected %s, got %s", string(payload), string(downloaded))
	}

	// 3. Download non-existent
	_, err = provider.Download(ctx, bucket, "non/existent/path.json")
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound, got %v", err)
	}

	// 4. Signed URL
	signedURL, err := provider.GetSignedURL(ctx, bucket, objectPath, 60*time.Second)
	if err != nil {
		t.Fatalf("GetSignedURL failed: %v", err)
	}
	if signedURL == "" {
		t.Errorf("expected signed URL, got empty string")
	}

	// 5. Tenant verification
	if err := provider.VerifyTenantAccess("tenant-alpha", objectPath); err != nil {
		t.Errorf("expected tenant verification to succeed, got %v", err)
	}
	if err := provider.VerifyTenantAccess("tenant-evil", objectPath); !errors.Is(err, ErrCrossTenantAccess) {
		t.Errorf("expected cross tenant violation, got %v", err)
	}

	// 6. Delete
	if err := provider.Delete(ctx, bucket, objectPath); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 7. Verify deletion
	_, err = provider.Download(ctx, bucket, objectPath)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound after deletion, got %v", err)
	}
}
