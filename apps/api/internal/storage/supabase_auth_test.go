package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestIsModernSecretKey(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"sb_secret_abcdef123456", true},
		{"sb_secret_test_key_with_long_entropy", true},
		{"  sb_secret_leading_whitespace  ", true},
		{"sb_secret_", true},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature", false},
		{"sb_anon_key_12345", false},
		{"sb_secret", false}, // missing trailing underscore
		{"service_role_secret", false},
		{"", false},
		{"   ", false},
		{"secret_sb_secret_key", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("key_%s", tt.key), func(t *testing.T) {
			got := IsModernSecretKey(tt.key)
			if got != tt.expected {
				t.Errorf("IsModernSecretKey(%q) = %v, expected %v", tt.key, got, tt.expected)
			}
		})
	}
}

type capturedRequest struct {
	Method       string
	Path         string
	APIKeyHeader string
	AuthHeader   string
	ContentType  string
	UpsertHeader string
	Body         []byte
}

func TestSupabaseStorageAuth_ModernSecretKey(t *testing.T) {
	const modernKey = "sb_secret_staging_opaque_key_9876543210"
	var mu sync.Mutex
	var captured []capturedRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = append(captured, capturedRequest{
			Method:       r.Method,
			Path:         r.URL.Path,
			APIKeyHeader: r.Header.Get("apikey"),
			AuthHeader:   r.Header.Get("Authorization"),
			ContentType:  r.Header.Get("Content-Type"),
			UpsertHeader: r.Header.Get("x-upsert"),
			Body:         body,
		})
		mu.Unlock()

		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Key":"kelvin-reports/tenant-1/scan-10/report.json"}`))
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"scan_id":"scan-10","status":"success"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"Successfully deleted"}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	provider, err := NewSupabaseStorageProvider(Config{
		URL:            server.URL,
		ServiceRoleKey: modernKey,
		ReportsBucket:  "kelvin-reports",
		EvidenceBucket: "kelvin-evidence",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	bucket := "kelvin-reports"
	objectPath := "tenant-1/scan-10/report.json"
	uploadPayload := []byte(`{"scan_id":"scan-10","status":"success"}`)

	// 1. Upload
	if err := provider.Upload(ctx, bucket, objectPath, "application/json", uploadPayload); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// 2. Download
	data, err := provider.Download(ctx, bucket, objectPath)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if string(data) != string(uploadPayload) {
		t.Errorf("Download returned %s, expected %s", string(data), string(uploadPayload))
	}

	// 3. Delete
	if err := provider.Delete(ctx, bucket, objectPath); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify captured requests
	mu.Lock()
	defer mu.Unlock()

	if len(captured) != 3 {
		t.Fatalf("expected 3 requests captured, got %d", len(captured))
	}

	expectedMethods := []string{http.MethodPost, http.MethodGet, http.MethodDelete}
	expectedPath := "/storage/v1/object/kelvin-reports/tenant-1/scan-10/report.json"

	for i, req := range captured {
		op := expectedMethods[i]
		if req.Method != op {
			t.Errorf("[%s] expected method %s, got %s", op, op, req.Method)
		}
		if req.Path != expectedPath {
			t.Errorf("[%s] expected path %s, got %s", op, expectedPath, req.Path)
		}

		// Modern secret key requirements:
		// - Set apikey: <secret-key>
		// - Do NOT set an Authorization Bearer header
		if req.APIKeyHeader != modernKey {
			t.Errorf("[%s] expected apikey header %q, got %q", op, modernKey, req.APIKeyHeader)
		}
		if req.AuthHeader != "" {
			t.Errorf("[%s] expected Authorization header to be empty/absent for modern secret key, got %q", op, req.AuthHeader)
		}
	}

	// Additional Upload-specific checks
	if captured[0].ContentType != "application/json" {
		t.Errorf("Upload expected Content-Type application/json, got %s", captured[0].ContentType)
	}
	if captured[0].UpsertHeader != "true" {
		t.Errorf("Upload expected x-upsert true, got %s", captured[0].UpsertHeader)
	}
}

func TestSupabaseStorageAuth_LegacyJWTKey(t *testing.T) {
	const legacyJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.mock_signature"
	var mu sync.Mutex
	var captured []capturedRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = append(captured, capturedRequest{
			Method:       r.Method,
			Path:         r.URL.Path,
			APIKeyHeader: r.Header.Get("apikey"),
			AuthHeader:   r.Header.Get("Authorization"),
			ContentType:  r.Header.Get("Content-Type"),
			UpsertHeader: r.Header.Get("x-upsert"),
			Body:         body,
		})
		mu.Unlock()

		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"scan_id":"legacy-scan"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	provider, err := NewSupabaseStorageProvider(Config{
		URL:            server.URL,
		ServiceRoleKey: legacyJWT,
		ReportsBucket:  "kelvin-reports",
		EvidenceBucket: "kelvin-evidence",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	bucket := "kelvin-evidence"
	objectPath := "tenant-legacy/scan-01/evidence.json"
	uploadPayload := []byte(`{"scan_id":"legacy-scan"}`)

	// 1. Upload
	if err := provider.Upload(ctx, bucket, objectPath, "application/json", uploadPayload); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// 2. Download
	if _, err := provider.Download(ctx, bucket, objectPath); err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// 3. Delete
	if err := provider.Delete(ctx, bucket, objectPath); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(captured) != 3 {
		t.Fatalf("expected 3 requests captured, got %d", len(captured))
	}

	expectedAuthHeader := "Bearer " + legacyJWT
	for _, req := range captured {
		// Legacy JWT requirements:
		// - Preserve apikey: <legacy-service-role-jwt>
		// - Preserve Authorization: Bearer <legacy-service-role-jwt>
		if req.APIKeyHeader != legacyJWT {
			t.Errorf("[%s] expected apikey header %q, got %q", req.Method, legacyJWT, req.APIKeyHeader)
		}
		if req.AuthHeader != expectedAuthHeader {
			t.Errorf("[%s] expected Authorization header %q, got %q", req.Method, expectedAuthHeader, req.AuthHeader)
		}
	}
}

func TestSupabaseStorage_HTTPErrorHandling_NoCredentialLeak(t *testing.T) {
	keysToTest := []struct {
		name string
		key  string
	}{
		{"modern_sb_secret", "sb_secret_super_secret_entropy_token_99999"},
		{"legacy_jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.sensitive_signature"},
	}

	for _, kt := range keysToTest {
		t.Run(kt.name, func(t *testing.T) {
			secretKey := kt.key

			// Mock server simulating error responses based on path
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.Path
				switch {
				case strings.Contains(path, "401_unauthorized"):
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"unauthorized access with key %s"}`, secretKey)))
				case strings.Contains(path, "403_forbidden"):
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"forbidden"}`))
				case strings.Contains(path, "404_not_found"):
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"error":"object not found"}`))
				case strings.Contains(path, "500_internal"):
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"internal database crash with %s"}`, secretKey)))
				default:
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad request"}`))
				}
			}))
			defer server.Close()

			provider, err := NewSupabaseStorageProvider(Config{
				URL:            server.URL,
				ServiceRoleKey: secretKey,
				ReportsBucket:  "kelvin-reports",
				EvidenceBucket: "kelvin-evidence",
			})
			if err != nil {
				t.Fatalf("failed to create provider: %v", err)
			}

			ctx := context.Background()

			// Test Upload with HTTP 500 error
			uploadErr := provider.Upload(ctx, "kelvin-reports", "tenant/assess/500_internal.json", "application/json", []byte(`{}`))
			if uploadErr == nil {
				t.Fatal("expected Upload to fail on HTTP 500, got nil")
			}
			if strings.Contains(uploadErr.Error(), secretKey) {
				t.Fatalf("credential leaked in upload error string: %s", uploadErr.Error())
			}

			// Test Download with HTTP 401 error
			_, downloadErr := provider.Download(ctx, "kelvin-reports", "tenant/assess/401_unauthorized.json")
			if downloadErr == nil {
				t.Fatal("expected Download to fail on HTTP 401, got nil")
			}
			if strings.Contains(downloadErr.Error(), secretKey) {
				t.Fatalf("credential leaked in download error string: %s", downloadErr.Error())
			}

			// Test Download with HTTP 404 (must return ErrObjectNotFound)
			_, notFoundErr := provider.Download(ctx, "kelvin-reports", "tenant/assess/404_not_found.json")
			if !errors.Is(notFoundErr, ErrObjectNotFound) {
				t.Fatalf("expected ErrObjectNotFound on 404, got %v", notFoundErr)
			}
			if strings.Contains(notFoundErr.Error(), secretKey) {
				t.Fatalf("credential leaked in 404 error string: %s", notFoundErr.Error())
			}

			// Test Delete with HTTP 403 error
			deleteErr := provider.Delete(ctx, "kelvin-reports", "tenant/assess/403_forbidden.json")
			if deleteErr == nil {
				t.Fatal("expected Delete to fail on HTTP 403, got nil")
			}
			if strings.Contains(deleteErr.Error(), secretKey) {
				t.Fatalf("credential leaked in delete error string: %s", deleteErr.Error())
			}

			// Test Delete with HTTP 404 (must return ErrObjectNotFound)
			deleteNotFoundErr := provider.Delete(ctx, "kelvin-reports", "tenant/assess/404_not_found.json")
			if !errors.Is(deleteNotFoundErr, ErrObjectNotFound) {
				t.Fatalf("expected ErrObjectNotFound on delete 404, got %v", deleteNotFoundErr)
			}
		})
	}
}

func TestSanitizeError(t *testing.T) {
	key := "sb_secret_very_sensitive_key_value"
	jwt := "eyJhbGciOiJIUzI1NiJ9.sensitive_payload"

	t.Run("Redacts secret when present in error", func(t *testing.T) {
		orig := fmt.Errorf("connection failed to host with token %s: dial tcp timeout", key)
		sanitized := sanitizeError(orig, key)
		if strings.Contains(sanitized.Error(), key) {
			t.Fatalf("expected secret to be redacted, got: %s", sanitized.Error())
		}
		if !strings.Contains(sanitized.Error(), "[REDACTED]") {
			t.Errorf("expected [REDACTED] in error string, got: %s", sanitized.Error())
		}
	})

	t.Run("Redacts multiple secrets", func(t *testing.T) {
		orig := fmt.Errorf("auth error with key=%s and bearer=%s", key, jwt)
		sanitized := sanitizeError(orig, key, jwt)
		if strings.Contains(sanitized.Error(), key) || strings.Contains(sanitized.Error(), jwt) {
			t.Fatalf("secrets leaked in error: %s", sanitized.Error())
		}
	})

	t.Run("Preserves error unchanged when secret not present", func(t *testing.T) {
		orig := errors.New("file not found")
		sanitized := sanitizeError(orig, key)
		if sanitized != orig {
			t.Errorf("expected identical error instance when secret absent")
		}
	})

	t.Run("Returns nil for nil error", func(t *testing.T) {
		if err := sanitizeError(nil, key); err != nil {
			t.Errorf("expected nil for nil error, got %v", err)
		}
	})
}
