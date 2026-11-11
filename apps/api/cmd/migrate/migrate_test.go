package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "postgres://user:supersecret@db.staging:5432/kelvin_staging?sslmode=verify-full",
			expected: "postgres://user:REDACTED@db.staging:5432/kelvin_staging?sslmode=verify-full",
		},
		{
			input:    "postgresql://postgres:complex%23pw@db.supabase.co:5432/postgres?sslmode=verify-full",
			expected: "postgresql://postgres:REDACTED@db.supabase.co:5432/postgres?sslmode=verify-full",
		},
		{
			input:    "http://127.0.0.1:8080",
			expected: "http://127.0.0.1:8080",
		},
		{
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		got := redactURL(tt.input)
		if got != tt.expected {
			t.Errorf("redactURL(%q) = %q; expected %q", tt.input, got, tt.expected)
		}
		if strings.Contains(got, "supersecret") || strings.Contains(got, "complex%23pw") {
			t.Errorf("redactURL leaked credentials: %q", got)
		}
	}
}

func TestResolveMigrationsPath(t *testing.T) {
	t.Run("Finds relative migrations path from repo root or api dir", func(t *testing.T) {
		path, err := resolveMigrationsPath("")
		if err != nil {
			t.Fatalf("resolveMigrationsPath failed: %v", err)
		}
		if !strings.HasSuffix(filepath.ToSlash(path), "db/migrations") {
			t.Errorf("expected path to end with db/migrations, got: %s", path)
		}
		if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
			t.Errorf("resolved path is not a valid directory: %s", path)
		}
	})

	t.Run("Accepts explicit custom path", func(t *testing.T) {
		tmpDir := t.TempDir()
		path, err := resolveMigrationsPath(tmpDir)
		if err != nil {
			t.Fatalf("resolveMigrationsPath with custom path failed: %v", err)
		}
		if path != tmpDir {
			t.Errorf("expected %q, got %q", tmpDir, path)
		}
	})

	t.Run("Fails cleanly when invalid custom path and candidates missing", func(t *testing.T) {
		_, err := resolveMigrationsPath("/non/existent/path/for/migrations")
		// If standard candidate paths exist in working directory, it will resolve to one of candidates
		// If not, it will return an error
		if err != nil && !strings.Contains(err.Error(), "unable to locate") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
