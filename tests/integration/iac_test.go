package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIaCStructureAndSecurity verifies that all production infrastructure modules
// and environments exist and do not contain plaintext hardcoded credentials.
func TestIaCStructureAndSecurity(t *testing.T) {
	// Find repository root
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	infraDir := filepath.Join(repoRoot, "infra", "terraform")

	if _, err := os.Stat(infraDir); os.IsNotExist(err) {
		t.Fatalf("Terraform directory does not exist: %s", infraDir)
	}

	requiredModules := []string{"networking", "security", "database", "broker", "storage", "compute", "ingress"}
	for _, mod := range requiredModules {
		modDir := filepath.Join(infraDir, "modules", mod)
		for _, f := range []string{"main.tf", "variables.tf", "outputs.tf"} {
			filePath := filepath.Join(modDir, f)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected Terraform module file %s does not exist", filePath)
			}
		}
	}

	requiredEnvs := []string{"dev", "staging", "prod"}
	for _, env := range requiredEnvs {
		envDir := filepath.Join(infraDir, "environments", env)
		for _, f := range []string{"main.tf", "variables.tf", "outputs.tf", "terraform.tfvars.example"} {
			filePath := filepath.Join(envDir, f)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected Terraform environment file %s does not exist", filePath)
			}
		}
	}

	// Secret check: Scan all .tf files for hardcoded secrets
	err = filepath.Walk(infraDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".tf") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		s := string(content)
		lower := strings.ToLower(s)
		for _, forbidden := range []string{"password = \"admin", "secret_key = \"AKIA", "token = \"ghp_"} {
			if strings.Contains(lower, strings.ToLower(forbidden)) {
				t.Errorf("Potential hardcoded credential in %s: %s", path, forbidden)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk infra dir: %v", err)
	}
}
