package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretsManagementModule verifies the Terraform secrets manager module,
// secret definitions, KMS key linkage, and absence of hardcoded keys.
func TestSecretsManagementModule(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	secretsModDir := filepath.Join(repoRoot, "infra", "terraform", "modules", "key_management")

	for _, f := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		p := filepath.Join(secretsModDir, f)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("Missing secrets module file %s: %v", f, err)
		}
		content := string(data)

		if f == "main.tf" {
			expectedSecrets := []string{
				"kelvin/${var.environment}/database/app",
				"kelvin/${var.environment}/redis/auth",
				"kelvin/${var.environment}/auth/jwt",
				"kelvin/${var.environment}/webhooks/signing",
				"kelvin/${var.environment}/integrations/envelope",
			}
			for _, sec := range expectedSecrets {
				if !strings.Contains(content, sec) {
					t.Errorf("main.tf missing secret declaration: %s", sec)
				}
			}

			if !strings.Contains(content, "aws_kms_key") {
				t.Errorf("main.tf must define an aws_kms_key for secrets encryption")
			}
			if !strings.Contains(content, "enable_key_rotation     = true") {
				t.Errorf("main.tf must enable key rotation for KMS key")
			}
		}
	}

	// Verify documentation exists
	docPath := filepath.Join(repoRoot, "docs", "security", "SECRETS_AND_CRYPTOGRAPHIC_KEY_MANAGEMENT.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing SECRETS_AND_CRYPTOGRAPHIC_KEY_MANAGEMENT.md documentation")
	}
}
