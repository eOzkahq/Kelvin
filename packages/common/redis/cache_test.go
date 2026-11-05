package redis

import (
	"testing"
)

func TestFormatTenantKey(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		resource   string
		id         string
		expected   string
	}{
		{
			name:     "full hierarchy",
			tenantID: "tenant-acme",
			resource: "assessment",
			id:       "run-456",
			expected: "kelvin:tenant-acme:assessment:run-456",
		},
		{
			name:     "empty id returns prefix resource",
			tenantID: "tenant-acme",
			resource: "ratelimit",
			id:       "",
			expected: "kelvin:tenant-acme:ratelimit",
		},
		{
			name:     "empty tenant defaults to global",
			tenantID: "",
			resource: "system",
			id:       "config",
			expected: "kelvin:global:system:config",
		},
		{
			name:     "empty resource defaults to default",
			tenantID: "tenant-beta",
			resource: "",
			id:       "lock",
			expected: "kelvin:tenant-beta:default:lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := FormatTenantKey(tt.tenantID, tt.resource, tt.id)
			if res != tt.expected {
				t.Errorf("FormatTenantKey() = %s, expected %s", res, tt.expected)
			}
		})
	}
}

func TestValidateTenantKey(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedTenantID string
		expectedValid    bool
	}{
		{
			name:             "matching tenant key",
			key:              "kelvin:tenant-123:cache:item-1",
			expectedTenantID: "tenant-123",
			expectedValid:    true,
		},
		{
			name:             "cross-tenant violation",
			key:              "kelvin:tenant-evil:cache:item-1",
			expectedTenantID: "tenant-123",
			expectedValid:    false,
		},
		{
			name:             "malformed key without prefix",
			key:              "raw-key-unprefixed",
			expectedTenantID: "tenant-123",
			expectedValid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := ValidateTenantKey(tt.key, tt.expectedTenantID)
			if valid != tt.expectedValid {
				t.Errorf("ValidateTenantKey(%s, %s) = %v, expected %v", tt.key, tt.expectedTenantID, valid, tt.expectedValid)
			}
		})
	}
}
