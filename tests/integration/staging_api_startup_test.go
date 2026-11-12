package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestStagingCompose_APIServiceContract verifies that deploy/staging/docker-compose.yml:
// - Declares all required Supabase and API environment variables
// - Configures the read-only Supabase CA certificate volume mount
// - Preserves all existing container hardening, resource limits, and loopback bindings
func TestStagingCompose_APIServiceContract(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	composePath := filepath.Join(repoRoot, "deploy", "staging", "docker-compose.yml")

	data, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read staging docker-compose.yml: %v", err)
	}
	content := string(data)

	// 1. Verify required environment variables are passed to the API service
	expectedEnvVars := []string{
		"KELVIN_API_ADDR: ${KELVIN_API_ADDR:-:8080}",
		"KELVIN_API_ALLOWED_ORIGINS: ${KELVIN_API_ALLOWED_ORIGINS}",
		"SUPABASE_URL: ${SUPABASE_URL}",
		"SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY}",
		"SUPABASE_STORAGE_BUCKET_REPORTS: ${SUPABASE_STORAGE_BUCKET_REPORTS}",
		"SUPABASE_STORAGE_BUCKET_EVIDENCE: ${SUPABASE_STORAGE_BUCKET_EVIDENCE}",
		"KELVIN_DATABASE_URL: ${KELVIN_DATABASE_URL}",
		"KELVIN_DATABASE_SSL_ROOT_CERT: ${SUPABASE_CA_CERT_PATH:-}",
		"REDIS_TLS_ENABLED: \"true\"",
		"KELVIN_JWT_SECRET: ${KELVIN_JWT_SECRET}",
		"KELVIN_EVIDENCE_SIGNING_KEY: ${KELVIN_EVIDENCE_SIGNING_KEY}",
	}

	for _, ev := range expectedEnvVars {
		if !strings.Contains(content, ev) {
			t.Errorf("staging docker-compose.yml api service missing expected environment variable: %s", ev)
		}
	}

	// 2. Verify CA certificate read-only volume bind mount
	expectedVolume := "${SUPABASE_CA_CERT_PATH}:${SUPABASE_CA_CERT_PATH}:ro"
	if !strings.Contains(content, expectedVolume) {
		t.Errorf("staging docker-compose.yml api service missing CA cert volume mount: %s", expectedVolume)
	}

	// 3. Verify security hardening settings remain intact
	securitySettings := []string{
		"read_only: true",
		"user: \"10001:10001\"",
		"no-new-privileges:true",
		"- ALL",
		"/tmp:rw,noexec,nosuid,size=256m",
		"\"127.0.0.1:8080:8080\"",
		"cpus: \"0.25\"",
		"memory: 1024M",
	}

	for _, setting := range securitySettings {
		if !strings.Contains(content, setting) {
			t.Errorf("staging docker-compose.yml api service missing security setting: %s", setting)
		}
	}
}

// TestStagingCompose_InterpolationAndValidation tests docker compose config evaluation
// using a safe test environment file containing non-sensitive dummy placeholders.
func TestStagingCompose_InterpolationAndValidation(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	composePath := filepath.Join(repoRoot, "deploy", "staging", "docker-compose.yml")

	// Safe dummy environment configuration
	dummyEnv := strings.Join([]string{
		"KELVIN_DATABASE_URL=postgres://kelvin_user:dummypw@db.dummy.supabase.co:5432/postgres?sslmode=verify-full",
		"SUPABASE_CA_CERT_PATH=/etc/pki/tls/certs/ca-bundle.crt",
		"KELVIN_JWT_SECRET=dummyjwtsecretfortestingstrictly32byteslong",
		"KELVIN_EVIDENCE_SIGNING_KEY=dummyevidencesigningkeyfortestingstrictly32byteslong",
		"SUPABASE_URL=https://dummy.supabase.co",
		"SUPABASE_SERVICE_ROLE_KEY=dummyservicerolekey123456",
		"SUPABASE_STORAGE_BUCKET_REPORTS=kelvin-reports",
		"SUPABASE_STORAGE_BUCKET_EVIDENCE=kelvin-evidence",
		"KELVIN_API_ALLOWED_ORIGINS=https://staging.kelvin.security",
	}, "\n")

	tempEnvFile := filepath.Join(t.TempDir(), "test_staging.env")
	if err := os.WriteFile(tempEnvFile, []byte(dummyEnv), 0600); err != nil {
		t.Fatalf("failed to write test env file: %v", err)
	}

	cmd := exec.Command("docker", "compose", "-f", composePath, "--env-file", tempEnvFile, "config")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("docker compose config validation failed: %v\nStderr: %s", err, stderr.String())
	}

	var composeDoc struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Volumes     []struct {
				Type     string `yaml:"type"`
				Source   string `yaml:"source"`
				Target   string `yaml:"target"`
				ReadOnly bool   `yaml:"read_only"`
			} `yaml:"volumes"`
			Ports []struct {
				HostIP    string `yaml:"host_ip"`
				Published string `yaml:"published"`
				Target    int    `yaml:"target"`
			} `yaml:"ports"`
		} `yaml:"services"`
	}

	if err := yaml.Unmarshal(stdout.Bytes(), &composeDoc); err != nil {
		t.Fatalf("failed to unmarshal docker compose config output: %v", err)
	}

	apiSvc, exists := composeDoc.Services["api"]
	if !exists {
		t.Fatal("api service missing in evaluated compose config")
	}

	// Verify environment variable propagation
	if apiSvc.Environment["SUPABASE_URL"] != "https://dummy.supabase.co" {
		t.Errorf("SUPABASE_URL not correctly propagated: %q", apiSvc.Environment["SUPABASE_URL"])
	}
	if apiSvc.Environment["SUPABASE_SERVICE_ROLE_KEY"] != "dummyservicerolekey123456" {
		t.Errorf("SUPABASE_SERVICE_ROLE_KEY not correctly propagated: %q", apiSvc.Environment["SUPABASE_SERVICE_ROLE_KEY"])
	}
	if apiSvc.Environment["SUPABASE_STORAGE_BUCKET_REPORTS"] != "kelvin-reports" {
		t.Errorf("SUPABASE_STORAGE_BUCKET_REPORTS not correctly propagated: %q", apiSvc.Environment["SUPABASE_STORAGE_BUCKET_REPORTS"])
	}
	if apiSvc.Environment["SUPABASE_STORAGE_BUCKET_EVIDENCE"] != "kelvin-evidence" {
		t.Errorf("SUPABASE_STORAGE_BUCKET_EVIDENCE not correctly propagated: %q", apiSvc.Environment["SUPABASE_STORAGE_BUCKET_EVIDENCE"])
	}
	if apiSvc.Environment["KELVIN_API_ADDR"] != ":8080" {
		t.Errorf("KELVIN_API_ADDR default not correctly evaluated: %q", apiSvc.Environment["KELVIN_API_ADDR"])
	}
	if apiSvc.Environment["KELVIN_API_ALLOWED_ORIGINS"] != "https://staging.kelvin.security" {
		t.Errorf("KELVIN_API_ALLOWED_ORIGINS not correctly propagated: %q", apiSvc.Environment["KELVIN_API_ALLOWED_ORIGINS"])
	}

	// Verify volume mount
	var caVolumeFound bool
	for _, vol := range apiSvc.Volumes {
		if vol.Source == "/etc/pki/tls/certs/ca-bundle.crt" &&
			vol.Target == "/etc/pki/tls/certs/ca-bundle.crt" &&
			vol.ReadOnly {
			caVolumeFound = true
			break
		}
	}
	if !caVolumeFound {
		t.Errorf("expected read-only bind mount for CA cert not found in api volumes: %v", apiSvc.Volumes)
	}

	// Verify loopback port binding
	var loopbackBound bool
	for _, p := range apiSvc.Ports {
		if p.HostIP == "127.0.0.1" && p.Published == "8080" && p.Target == 8080 {
			loopbackBound = true
			break
		}
	}
	if !loopbackBound {
		t.Errorf("API port is not strictly bound to 127.0.0.1:8080: %v", apiSvc.Ports)
	}
}
