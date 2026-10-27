package database

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNormalizeSourceURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"db/migrations", "file://db/migrations"},
		{"file://db/migrations", "file://db/migrations"},
		{"C:\\projects\\kelvin\\migrations", "file://C:/projects/kelvin/migrations"},
		{"file://C:\\projects\\kelvin\\migrations", "file://C:/projects/kelvin/migrations"},
	}

	for _, tt := range tests {
		actual := normalizeSourceURL(tt.input)
		if actual != tt.expected {
			t.Errorf("normalizeSourceURL(%q) = %q; expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestNewMigrator_Validation(t *testing.T) {
	mig := NewMigrator("db/migrations", "invalid-url", zap.NewNop())
	if mig == nil {
		t.Fatal("expected migrator instance, got nil")
	}

	// Attempting to instantiate with malformed URL should fail fast
	_, err := mig.instance()
	if err == nil {
		t.Fatal("expected error on malformed database URL, got nil")
	}
	if !strings.Contains(err.Error(), "failed to initialize golang-migrate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

